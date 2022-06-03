//
// qscan
// Copyright (C) 2022  0xor0ne
// This program is free software: you can redistribute it and/or modify it under
// the terms of the GNU General Public License as published by the Free Software
// Foundation, either version 3 of the License, or (at your option) any later
// version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT ANY
// WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
// PARTICULAR PURPOSE. See the GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along with
// this program. If not, see <https://www.gnu.org/licenses/>.
//
use qscan::qscanner::{
    QSPrintMode, QScanTcpConnectResult, QScanTcpConnectState, QScanType, QScanner,
};

use clap::Parser;
use tokio::runtime::Runtime;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[clap(
        long,
        help = "Comma separated list of targets to scan. \
        A target can be an IP, a set of IPs in CIDR notation, a domain name \
        or a path to a file containing one of the previous for each line. \
        E.g., '8.8.8.8', '192.168.1.0/24', 'www.google.com,/tmp/ips.txt'"
    )]
    targets: String,

    #[clap(
        long,
        help = "Comma separate list of ports (or port ranges) to scan for each target. \
           E.g., '80', '22,443', '1-1024,8080'"
    )]
    ports: String,

    #[clap(long, default_value_t = 5000, help = "Parallel scan")]
    batch: u16,

    #[clap(
        long,
        default_value_t = 1500,
        help = "Timeout in ms. If the timeout expires the port is considered close"
    )]
    timeout: u64,

    #[clap(
        long,
        default_value_t = 1,
        help = "Number of maximum retries for each target:port pair"
    )]
    tries: u8,

    #[clap(
        long,
        default_value_t = 3,
        help = "Console output mode:
  - 0: suppress console output;
  - 1: print ip:port for open ports at the end of the scan;
  - 2: print ip:port:<OPEN|CLOSE> at the end of the scan;
  - 3: print ip:port for open ports as soon as they are found;
  - 4: print ip:port:<OPEN:CLOSE> as soon as the scan for a
       target ends;
        "
    )]
    printlevel: u8,
}

/// Simple async tcp connect scanner
pub fn main() {
    let args = Args::parse();
    let addresses = args.targets;
    let ports = args.ports;
    let batch = args.batch;
    let timeout = args.timeout;
    let tries = args.tries;

    let mut scanner = QScanner::new(&addresses, &ports);
    scanner.set_scan_type(QScanType::TcpConnect);

    scanner.set_batch(batch);
    scanner.set_timeout_ms(timeout);
    scanner.set_ntries(tries);

    let mut no_output = false;

    match args.printlevel {
        0 => no_output = true,
        1 | 2 => scanner.set_print_mode(QSPrintMode::NonRealTime),
        3 => scanner.set_print_mode(QSPrintMode::RealTime),
        4 => scanner.set_print_mode(QSPrintMode::RealTimeAll),
        _ => {
            panic!("Unknown print mode {} (allowed 0-4)", args.printlevel);
        }
    }

    let res: Vec<QScanTcpConnectResult> =
        Runtime::new().unwrap().block_on(scanner.scan_tcp_connect());

    if !no_output && (args.printlevel == 1 || args.printlevel == 2) {
        for sa in &res {
            if sa.state == QScanTcpConnectState::Open {
                if args.printlevel == 1 {
                    println!("{}", sa.target);
                } else {
                    println!("{}:OPEN", sa.target);
                }
            } else if args.printlevel == 2 {
                println!("{}:CLOSED", sa.target);
            }
        }
    }
}