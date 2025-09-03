use hickory_resolver::{Resolver, name_server::ConnectionProvider, proto::rr::RecordType};
use serde::Serialize;
use std::net::IpAddr;
use tokio::runtime::Runtime;

#[derive(Debug, Serialize)]
pub struct NameServer {
    pub names: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ips: Option<Vec<IpAddr>>,
}

pub fn query_ns<T: ConnectionProvider>(
    target: &str,
    io_loop: &Runtime,
    resolver: &Resolver<T>,
) -> Option<NameServer> {
    let lookup_ns_future = resolver.lookup(target, RecordType::NS);
    match io_loop.block_on(lookup_ns_future) {
        Ok(response_ns) => {
            let ns_records = response_ns
                .into_iter()
                .filter_map(|r| r.into_ns().ok())
                .map(|name| name.to_string())
                .collect::<Vec<_>>();
            let ns_ips = ns_records
                .iter()
                .map(|ns| query_ipv4_ipv6(ns, io_loop, resolver))
                .filter_map(|ips| ips)
                .flatten()
                .collect::<Vec<_>>();
            if ns_ips.is_empty() {
                Some(NameServer {
                    names: ns_records,
                    ips: None,
                })
            } else {
                Some(NameServer {
                    names: ns_records,
                    ips: Some(ns_ips),
                })
            }
        }
        Err(_) => None,
    }
}

pub fn query_cname<T: ConnectionProvider>(
    target: &str,
    io_loop: &Runtime,
    resolver: &Resolver<T>,
) -> Option<Vec<String>> {
    let lookup_cname_future = resolver.lookup(target, RecordType::CNAME);
    match io_loop.block_on(lookup_cname_future) {
        Ok(response_cname) => {
            let cnames = response_cname
                .into_iter()
                .filter_map(|r| r.into_cname().ok())
                .map(|name| name.to_string())
                .collect::<Vec<_>>();
            if cnames.is_empty() {
                None
            } else {
                Some(cnames)
            }
        }
        Err(_) => None,
    }
}

pub fn query_ipv6<T: ConnectionProvider>(
    target: &str,
    io_loop: &Runtime,
    resolver: &Resolver<T>,
) -> Option<Vec<IpAddr>> {
    let lookup_aaaa_future = resolver.ipv6_lookup(target);
    match io_loop.block_on(lookup_aaaa_future) {
        Ok(response_aaaa) => {
            let ipv6_addrs = response_aaaa
                .into_iter()
                .map(|addr| IpAddr::from(addr.0))
                .collect::<Vec<_>>();
            Some(ipv6_addrs)
        }
        Err(_) => None,
    }
}

pub fn query_ipv4<T: ConnectionProvider>(
    target: &str,
    io_loop: &Runtime,
    resolver: &Resolver<T>,
) -> Option<Vec<IpAddr>> {
    let lookup_a_future = resolver.ipv4_lookup(target);
    match io_loop.block_on(lookup_a_future) {
        Ok(response_a) => {
            let ipv4_addrs = response_a
                .into_iter()
                .map(|addr| IpAddr::from(addr.0))
                .collect::<Vec<_>>();
            Some(ipv4_addrs)
        }
        Err(_) => None,
    }
}

pub fn query_ipv4_ipv6<T: ConnectionProvider>(
    target: &str,
    io_loop: &Runtime,
    resolver: &Resolver<T>,
) -> Option<Vec<IpAddr>> {
    let ipv4 = query_ipv4(target, io_loop, resolver);
    let ipv6 = query_ipv6(target, io_loop, resolver);
    let mut ip: Vec<IpAddr> = Vec::new();
    if let Some(v4) = ipv4 {
        ip.extend(v4);
    }
    if let Some(v6) = ipv6 {
        ip.extend(v6);
    }
    if ip.is_empty() { None } else { Some(ip) }
}
