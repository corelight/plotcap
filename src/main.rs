// Copyright (c) 2022, Corelight, Inc. All rights reserved.

use std::fs::{metadata, set_permissions, File};
use std::io::{BufWriter, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use byte_unit::Byte;
use chrono::prelude::*;
use chrono::OutOfRangeError;
use chrono::{Duration, NaiveDateTime};
use clap::Parser;
use humantime::{format_duration, parse_duration};
use pcap_parser::{create_reader, Block, PcapBlockOwned, PcapError};

const POWER_BITS: u8 = 0x7f;
const EXPONENT_FLAG_BIT: u8 = 0x80;
const NANOS_PER_SECOND: u64 = 1_000_000_000;
const NANOS_PER_MICRO: u32 = 1_000;
const MICROS_PER_SECOND: f64 = 1e6f64;

/// make_pcapng_timestamp returns a function that will convert the high:low pcapng
/// timestamp parts into a NaiveDateTime given the value of if_tsresol.
fn make_pcapng_timestamp(if_tsresol: u8) -> impl Fn(u32, u32) -> NaiveDateTime {
    let exponent = if_tsresol & POWER_BITS; // TODO: add check for exponent > 64
    let flag = if_tsresol & EXPONENT_FLAG_BIT == EXPONENT_FLAG_BIT;

    let divisor = if flag {
        2u64.pow(exponent as u32)
    } else {
        10u64.pow(exponent as u32)
    };

    move |ts_high: u32, ts_low: u32| -> NaiveDateTime {
        let ts = (ts_high as u64) << 32 | (ts_low as u64);
        let (secs, nsecs) = if flag {
            // base 2, so power of 10 would mean 1/1024 second
            // TODO: benchmark the bit shifting to see if it is really faster than
            //       the the division and modular arithmetic in the base 10 case below.
            (ts >> exponent, (ts & (exponent as u64 - 1)) / divisor)
        } else {
            // base 10 so power of 3 would mean 1/1000 second
            (ts / divisor, (ts % divisor * NANOS_PER_SECOND) / divisor)
        };
        NaiveDateTime::from_timestamp_opt(secs as i64, nsecs as u32).unwrap()
    }
}

#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
struct Cli {
    #[clap(short = 'r', long = "read", value_parser, value_name = "FILE")]
    input_filename: PathBuf,

    #[clap(short = 'o', long = "output", value_parser, value_name = "FILE")]
    output_filename: PathBuf,

    #[clap(short = 'i', long = "interval", parse(try_from_str = parse_duration_arg), value_name = "INTERVAL", default_value = "1 second")]
    minimum_reporting_period: chrono::Duration,
}

/// parse_duration_arg adapts the str-derived core::time::Duration to a chrono::Duration
fn parse_duration_arg(arg: &str) -> std::result::Result<Duration, OutOfRangeError> {
    Duration::from_std(parse_duration(arg).unwrap())
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let infile = File::open(&cli.input_filename).context(format!(
        "Unable to open input file {}",
        &cli.input_filename.display()
    ))?;

    let mut reader = create_reader(65536, &infile).context(format!(
        "Unable to read input file {}",
        cli.input_filename.display()
    ))?;

    let outfile = File::create(&cli.output_filename).context(format!(
        "Unable to open output file {}",
        cli.output_filename.display()
    ))?;

    let mut writer = BufWriter::new(&outfile);

    let epoch_ts: NaiveDateTime = NaiveDateTime::from_timestamp_opt(0, 0).unwrap();
    let mut this_packet_ts = epoch_ts;
    let mut first_packet_ts = epoch_ts;
    let mut previous_packet_ts = epoch_ts;
    let mut packet_count: u32 = 0;
    let mut byte_count_wire: u32 = 0;
    let mut byte_count_capture: u32 = 0;
    let mut eof = false;
    let mut file_type = "unknown";

    let mut pcapng_timestamp = make_pcapng_timestamp(6u8);

    write!(&mut writer, "#!/usr/bin/env -S gnuplot -p\n#\n")?;

    writeln!(
        &mut writer,
        "# Generated with plotcap (https://github.com/corelight/plotcap)"
    )?;
    writeln!(
        &mut writer,
        "# Input file: {}",
        cli.input_filename.display()
    )?;
    write!(&mut writer, "# Date: {}\n\n", Utc::now())?;

    writeln!(&mut writer, "$data << EOD")?;

    loop {
        match reader.next() {
            Ok((offset, block)) => {
                let (packet_bytes_wire, packet_bytes_capture, ts) = match block {
                    PcapBlockOwned::Legacy(b) => (
                        b.origlen,
                        b.caplen,
                        NaiveDateTime::from_timestamp_opt(
                            b.ts_sec as i64,
                            b.ts_usec * NANOS_PER_MICRO,
                        )
                        .unwrap(),
                    ),
                    PcapBlockOwned::NG(b) => {
                        file_type = "pcapng";
                        match b {
                            Block::EnhancedPacket(b) => {
                                (b.origlen, b.caplen, pcapng_timestamp(b.ts_high, b.ts_low))
                            }
                            Block::SimplePacket(_) => {
                                panic!(
                                    "pcapng file contains simple packets, which are unsupported"
                                );
                            }
                            Block::InterfaceDescription(i) => {
                                pcapng_timestamp = make_pcapng_timestamp(i.if_tsresol);
                                reader.consume(offset);
                                continue;
                            }
                            _ => {
                                // other blocks we don't care about but we must consume
                                reader.consume(offset);
                                continue;
                            }
                        }
                    }
                    PcapBlockOwned::LegacyHeader(_) => {
                        file_type = "pcap";
                        reader.consume(offset);
                        continue;
                    }
                };

                this_packet_ts = ts;

                reader.consume(offset);

                if previous_packet_ts == epoch_ts {
                    first_packet_ts = this_packet_ts;
                    previous_packet_ts = this_packet_ts;
                }

                byte_count_capture += packet_bytes_capture;
                byte_count_wire += packet_bytes_wire;
                packet_count += 1;
            }
            Err(PcapError::Incomplete) => {
                reader.refill().unwrap();
                continue;
            }
            Err(PcapError::Eof) => {
                eof = true;
            }
            Err(e) => panic!("error while reading: {:?}", e),
        }

        let elapsed_since_last_packet = this_packet_ts - previous_packet_ts;

        if elapsed_since_last_packet >= cli.minimum_reporting_period || (eof && packet_count > 1) {
            let elapsed_since_last_packet_secs =
                elapsed_since_last_packet.num_nanoseconds().unwrap() as f64 / 1e+9f64;
            let elapsed_since_first_packet_secs = (this_packet_ts - first_packet_ts)
                .num_microseconds()
                .unwrap() as f64
                / MICROS_PER_SECOND;

            let rate_packets = f64::from(packet_count) / elapsed_since_last_packet_secs;
            let rate_wire_bytes = f64::from(byte_count_wire) / elapsed_since_last_packet_secs;
            let rate_capture_bytes = f64::from(byte_count_capture) / elapsed_since_last_packet_secs;

            // Gnuplot data row
            writeln!(
                &mut writer,
                "{} {:.2} {:.2} {:.2}",
                elapsed_since_first_packet_secs, rate_packets, rate_wire_bytes, rate_capture_bytes
            )?;

            previous_packet_ts = this_packet_ts;
            packet_count = 0;
            byte_count_wire = 0;
            byte_count_capture = 0;
        }

        if eof {
            break;
        }
    }

    let size =
        Byte::from_bytes(infile.metadata().unwrap().len() as u128).get_appropriate_unit(true);

    let fname = Path::new(&cli.input_filename).file_name().unwrap();

    let dur = format_duration((previous_packet_ts - first_packet_ts).to_std().unwrap());

    write!(
        &mut writer,
        "EOD

set title 'Packet/data rate plot for {} file {:?} ({} / {})'
set xlabel 'Time'
set ylabel 'Packet rate'
set y2label 'Data rate'
set format y '%.0s%cpps'
set format y2 '%.0s%cbps'
set ytics nomirror
set y2tics nomirror
set xtics time format '%tH:%tM:%tS'
set xtics rotate by -45
plot    $data u 1:2 with lines axis x1y1 title 'Packets/s', \\
        $data u 1:($3*8) with lines axis x1y2 title 'Bits/s on the wire', \\
        $data u 1:($4*8) with points axis x1y2 title 'Bits/s captured'
pause mouse close\n",
        file_type, fname, size, dur
    )?;

    let mut perms = metadata(&cli.output_filename)
        .context(format!(
            "Unable to get file permissions for {}",
            cli.output_filename.display()
        ))?
        .permissions();

    perms.set_mode(0o755);

    set_permissions(&cli.output_filename, perms).context(format!(
        "Unable to set file permissions for {}",
        cli.output_filename.display()
    ))?;

    Ok(())
}
