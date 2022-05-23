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

use std::net::IpAddr;
use std::net::SocketAddr;
use std::net::ToSocketAddrs;

use std::fs::File;
use std::io::BufRead;
use std::io::BufReader;
use std::path::Path;

use std::num::NonZeroU8;
use std::time::Duration;

use tokio::io;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::time::error::Elapsed;
use tokio::time::timeout;

use cidr_utils::cidr::IpCidr;

use futures::stream::{FuturesUnordered, StreamExt};

use trust_dns_resolver::{
    config::{ResolverConfig, ResolverOpts},
    Resolver,
};

/// Simple async network scanner
#[derive(Debug)]
pub struct QScanner {
    ips: Vec<IpAddr>,
    ports: Vec<u16>,
    batch: u16,
    to: Duration,
    tries: NonZeroU8,
}

impl QScanner {
    /// Create a new QScanner
    ///
    /// # Arguments
    ///
    /// * `addresses` - IPs string, comma separated and CIDR notation
    /// * `ports` - ports string, comma separated and ranges
    /// * `batch` - concurrent scans
    /// * `to_ms` - timeout in milliseconds
    /// * `tries` - retries for each pair of ip:port
    ///
    /// # Examples
    ///
    /// ```
    /// use qscan::QScanner;
    /// let scanner1 = QScanner::new("127.0.0.1", "80", 1000, 1000, 1);
    /// let scanner2 = QScanner::new("127.0.0.1,127.0.1.0/24", "80,443,1024-2048", 1000, 1000, 1);
    /// ```
    ///
    pub fn new(addresses: &str, ports: &str, batch: u16, to_ms: u64, tries: u8) -> Self {
        Self {
            ips: Self::addresses_parse(addresses),
            ports: Self::ports_parse(ports),
            batch,
            to: Duration::from_millis(to_ms),
            tries: NonZeroU8::new(std::cmp::max(tries, 1)).unwrap(),
        }
    }

    /// Parse ports strings, comma separated strings and ranges.
    /// E.g., "80", "80,443", "80,100-200,443"
    fn ports_parse(ports: &str) -> Vec<u16> {
        let mut pv: Vec<u16> = Vec::new();
        let ps: String = ports.chars().filter(|c| !c.is_whitespace()).collect();

        for p in ps.split(',') {
            let range = p
                .split('-')
                .map(str::parse)
                .collect::<Result<Vec<u16>, std::num::ParseIntError>>()
                .unwrap();

            match range.len() {
                1 => pv.push(range[0]),
                2 => pv.extend(range[0]..=range[1]),
                _ => {
                    panic!("Invalid Range: {:?}", range);
                }
            }
        }

        pv
    }

    /// Parse IP addresses strings.
    /// E.g., "1.2.3.4", "1.2.3.4,8.8.8.8", 192.168.1.0/24"
    fn addresses_parse(addresses: &str) -> Vec<IpAddr> {
        let mut ips: Vec<IpAddr> = Vec::new();
        let alt_resolver =
            Resolver::new(ResolverConfig::cloudflare_tls(), ResolverOpts::default()).unwrap();

        let addrs: String = addresses.chars().filter(|c| !c.is_whitespace()).collect();

        for addr in addrs.split(',') {
            let parsed_addr = Self::address_parse(addr, &alt_resolver);

            if !parsed_addr.is_empty() {
                ips.extend(parsed_addr);
            } else {
                // Check if we have a file to read addresses from
                let file_path = Path::new(addr);
                if !file_path.is_file() {
                    println!("Error: not a file {:?}", addr);
                    continue;
                }

                if let Ok(x) = QScanner::read_addresses_from_file(file_path, &alt_resolver) {
                    ips.extend(x);
                } else {
                    println!("Error: unknown target {:?}", addr);
                }
            }
        }

        ips
    }

    fn address_parse(addr: &str, resolver: &Resolver) -> Vec<IpAddr> {
        IpCidr::from_str(&addr)
            .map(|cidr| cidr.iter().collect())
            .ok()
            .or_else(|| {
                format!("{}:{}", &addr, 80)
                    .to_socket_addrs()
                    .ok()
                    .map(|mut iter| vec![iter.next().unwrap().ip()])
            })
            .unwrap_or_else(|| Self::domain_name_resolve_to_ip(addr, resolver))
    }

    fn domain_name_resolve_to_ip(source: &str, alt_resolver: &Resolver) -> Vec<IpAddr> {
        let mut ips: Vec<IpAddr> = Vec::new();

        if let Ok(addrs) = source.to_socket_addrs() {
            for ip in addrs {
                ips.push(ip.ip());
            }
        } else if let Ok(addrs) = alt_resolver.lookup_ip(source) {
            ips.extend(addrs.iter());
        }

        ips
    }

    // Read ips or fomain name from a file
    fn read_addresses_from_file(
        addrs_file_path: &Path,
        backup_resolver: &Resolver,
    ) -> Result<Vec<IpAddr>, std::io::Error> {
        let file = File::open(addrs_file_path)?;
        let reader = BufReader::new(file);
        let mut ips: Vec<IpAddr> = Vec::new();

        for (idx, address_line) in reader.lines().enumerate() {
            if let Ok(address) = address_line {
                ips.extend(QScanner::address_parse(&address, backup_resolver));
            } else {
                println!("Error: Line {} in file is not valid", idx);
            }
        }

        Ok(ips)
    }

    /// Async TCP connect scan
    ///
    /// # Args
    ///
    /// * `rt_print` - Print open ports as soon as they are found
    ///
    /// # Return
    ///
    /// A vector of [SocketAddr] for each open port found.
    ///
    /// # Examples
    ///
    /// ```
    /// use qscan::QScanner;
    /// use tokio::runtime::Runtime;
    /// let scanner = QScanner::new("127.0.0.1", "80", 1000, 1000, 1);
    /// let res = Runtime::new().unwrap().block_on(scanner.scan_tcp_connect(true));
    /// ```
    ///
    pub async fn scan_tcp_connect(&self, rt_print: bool) -> Vec<SocketAddr> {
        let mut open_soc: Vec<SocketAddr> = Vec::new();
        let mut sock_it: sockiter::SockIter = sockiter::SockIter::new(&self.ips, &self.ports);
        let mut ftrs = FuturesUnordered::new();

        for _ in 0..self.batch {
            if let Some(socket) = sock_it.next() {
                ftrs.push(self.scan_socket_tcp_connect(socket));
            } else {
                break;
            }
        }

        while let Some(result) = ftrs.next().await {
            if let Some(socket) = sock_it.next() {
                ftrs.push(self.scan_socket_tcp_connect(socket));
            }

            if let Ok(socket) = result {
                if rt_print {
                    println!("{}", socket);
                }

                open_soc.push(socket);
            }
        }

        open_soc
    }

    async fn scan_socket_tcp_connect(&self, socket: SocketAddr) -> io::Result<SocketAddr> {
        let tries = self.tries.get();

        for ntry in 0..tries {
            match self.tcp_connect(socket).await {
                Ok(Ok(mut x)) => {
                    x.shutdown().await?;
                    return Ok(socket);
                }
                Ok(Err(e)) => {
                    let mut err_str = e.to_string();

                    if err_str.to_lowercase().contains("too many open files") {
                        panic!("Too many open files, reduce batch size {}", self.batch);
                    }

                    if ntry == tries - 1 {
                        err_str.push(' ');
                        err_str.push_str(&socket.ip().to_string());
                        return Err(io::Error::new(io::ErrorKind::Other, err_str));
                    }
                }
                Err(e) => {
                    let mut err_str = e.to_string();

                    if ntry == tries - 1 {
                        err_str.push(' ');
                        err_str.push_str(&socket.ip().to_string());
                        return Err(io::Error::new(io::ErrorKind::Other, err_str));
                    }
                }
            };
        }
        unreachable!();
    }

    async fn tcp_connect(&self, socket: SocketAddr) -> Result<io::Result<TcpStream>, Elapsed> {
        // See https://stackoverflow.com/questions/30022084/how-do-i-set-connect-timeout-on-tcpstream
        timeout(self.to, TcpStream::connect(socket)).await
    }
}

mod sockiter {
    use itertools::{iproduct, Product};
    use std::net::{IpAddr, SocketAddr};

    pub struct SockIter<'a> {
        prod: Product<Box<std::slice::Iter<'a, u16>>, Box<std::slice::Iter<'a, std::net::IpAddr>>>,
    }

    impl<'a> SockIter<'a> {
        pub fn new(ips: &'a [IpAddr], ports: &'a [u16]) -> Self {
            let ports = Box::new(ports.iter());
            let ips = Box::new(ips.iter());
            Self {
                prod: iproduct!(ports, ips),
            }
        }
    }

    impl<'s> Iterator for SockIter<'s> {
        type Item = SocketAddr;

        fn next(&mut self) -> Option<Self::Item> {
            self.prod
                .next()
                .map(|(port, ip)| SocketAddr::new(*ip, *port))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use trust_dns_resolver::{
        config::{ResolverConfig, ResolverOpts},
        Resolver,
    };

    use tokio::runtime::Runtime;

    #[test]
    fn parse_simple_address() {
        let res = super::QScanner::addresses_parse("127.0.0.1");
        assert_eq!(res, vec!["127.0.0.1".parse::<IpAddr>().unwrap()]);
    }

    #[test]
    fn parse_multiple_addresses() {
        let res = super::QScanner::addresses_parse("127.0.0.1,127.0.0.2");
        assert_eq!(
            res,
            vec![
                "127.0.0.1".parse::<IpAddr>().unwrap(),
                "127.0.0.2".parse::<IpAddr>().unwrap(),
            ]
        );
    }

    #[test]
    fn parse_cidr() {
        let res = super::QScanner::addresses_parse("127.0.0.10/31");
        assert_eq!(
            res,
            vec![
                "127.0.0.10".parse::<IpAddr>().unwrap(),
                "127.0.0.11".parse::<IpAddr>().unwrap(),
            ]
        );
    }

    #[test]
    fn parse_cidr_and_addresses() {
        let res = super::QScanner::addresses_parse("127.0.0.1,127.0.0.10/31, 127.0.0.2");
        assert_eq!(
            res,
            vec![
                "127.0.0.1".parse::<IpAddr>().unwrap(),
                "127.0.0.10".parse::<IpAddr>().unwrap(),
                "127.0.0.11".parse::<IpAddr>().unwrap(),
                "127.0.0.2".parse::<IpAddr>().unwrap(),
            ]
        );
    }

    #[test]
    fn parse_single_port() {
        let res = super::QScanner::ports_parse("80");
        assert_eq!(res, vec![80]);
    }

    #[test]
    fn parse_multiple_ports() {
        let res = super::QScanner::ports_parse("80, 443,8080");
        assert_eq!(res, vec![80, 443, 8080]);
    }

    #[test]
    fn parse_ports_range() {
        let res = super::QScanner::ports_parse("80-83");
        assert_eq!(res, vec![80, 81, 82, 83]);
    }

    #[test]
    fn parse_ports_mixed() {
        let res = super::QScanner::ports_parse("21,80-83,443,8080-8081");
        assert_eq!(res, vec![21, 80, 81, 82, 83, 443, 8080, 8081]);
    }

    #[test]
    fn scan_tcp_connect_google_dns() {
        let scanner = super::QScanner::new("8.8.8.8", "53,54,55-60", 5000, 2500, 1);
        let res = Runtime::new()
            .unwrap()
            .block_on(scanner.scan_tcp_connect(true));
        assert_eq!(
            res,
            vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53)]
        );
    }

    #[test]
    fn resolve_localhost() {
        let resolver =
            Resolver::new(ResolverConfig::cloudflare_tls(), ResolverOpts::default()).unwrap();
        let res = super::QScanner::domain_name_resolve_to_ip("localhost", &resolver);
        assert_eq!(res, vec![IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))]);
    }

    #[test]
    fn resolve_lhost() {
        let resolver =
            Resolver::new(ResolverConfig::cloudflare_tls(), ResolverOpts::default()).unwrap();
        let res = super::QScanner::domain_name_resolve_to_ip("www.google.com", &resolver);
        assert!(res.len() > 0);
    }
}
