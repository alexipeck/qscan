use std::{process::exit, net::{IpAddr, Ipv4Addr}, collections::HashMap};
use local_ip_address::{local_ip};
use qscan::{QSPrintMode, QScanResult, QScanTcpConnectState, QScanType, QScanner};
use tokio::runtime::Runtime;

fn main() {
    match local_ip() {
        Ok(local_ip_address) => {
            match local_ip_address.is_ipv4() {
                true => {
                    let octets = local_ip_address.to_string().split('.')
                        .map(|s| s.parse::<u8>().unwrap_or_else(|_| panic!("d9db0de9-ed11-485e-a7ca-4c5a5567e6ec: Couldn't parse octet from IPV4 address.")))
                        .collect::<Vec<u8>>();

                    //remove host device from pool
                    let mut octet_range = (1..=255).collect::<Vec<u8>>();
                    octet_range.remove(octet_range.iter().position(|i|*i == octets[3]).unwrap_or_else(|| panic!("64b26286-7ba0-4b6f-8f06-0a13f10c3f69: Error finding position of value to be removed.")));

                    let ip_vec = octet_range.iter().map(|last_octet| {
                        IpAddr::V4(Ipv4Addr::new(octets[0], octets[1], octets[2], *last_octet))
                    }).collect::<Vec<IpAddr>>();
                    let all_possible_ports = (u16::MIN..=u16::MAX).collect::<Vec<u16>>();

                    let mut scanner = QScanner::new_from_vecs(ip_vec, all_possible_ports);
                    scanner.set_batch(5000);
                    scanner.set_timeout_ms(2000);
                    scanner.set_ntries(1);
                    scanner.set_scan_type(QScanType::TcpConnect);
                    scanner.set_print_mode(QSPrintMode::NonRealTime);

                    let qscan_result: &Vec<QScanResult> = Runtime::new().unwrap().block_on(scanner.scan_tcp_connect());
                    let mut target_port_tracker: HashMap<IpAddr, Vec<u16>> = HashMap::new();
                    for qscan_result in qscan_result {
                        if let QScanResult::TcpConnect(tcp_scan_result) = qscan_result {
                            if tcp_scan_result.state == QScanTcpConnectState::Open {
                                target_port_tracker.entry(tcp_scan_result.target.ip()).or_default().push(tcp_scan_result.target.port());
                            }
                        }
                    }
                    for (ip, ports) in target_port_tracker {
                        let mut iter = ports.iter();
                        let mut ports_string = String::new();
                        ports_string.push_str(&iter.next().unwrap().to_string());
                        for t in iter {
                            ports_string.push_str(&format!(", {}", t));
                        }
                        println!("{}: {}", ip, ports_string);
                    }
                },
                false => {
                    println!("62c2c7bc-7ed0-4b36-879f-6ddbeecbc06b: Program doesn't currently handle IPV6, exiting.");
                    exit(1);
                },
            }
        },
        Err(err) => {
            println!("94fc5e14-815a-4f65-873c-90b03766ee35: Couldn't retrieve local IP: {}", err);
        },
    }
}