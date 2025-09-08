use super::{Asn, find_asn};
use futures::future::join_all;
use hickory_resolver::{Resolver, name_server::ConnectionProvider, proto::rr::RecordType};
use ip2asn::IpAsnMap;
use serde::Serialize;
use std::net::IpAddr;

#[derive(Debug, Serialize)]
pub struct NameServer {
    pub names: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ips: Option<Vec<IpAddr>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub asn: Option<Vec<Asn>>,
}

pub async fn query_ns<T: ConnectionProvider>(
    target: &str,
    resolver: &Resolver<T>,
    ip2asn_map: &IpAsnMap,
) -> Option<NameServer> {
    let lookup_ns_future = resolver.lookup(target, RecordType::NS);
    match lookup_ns_future.await {
        Ok(response_ns) => {
            // fetch ns records
            let ns_records = response_ns
                .into_iter()
                .filter_map(|r| r.into_ns().ok())
                .map(|name| name.to_string())
                .collect::<Vec<_>>();
            // fetch ns ips
            let futures = ns_records.iter().map(|ns| query_ipv4_ipv6(ns, resolver));
            let parallel_results = join_all(futures).await;
            let ns_ips = parallel_results
                .into_iter()
                .filter_map(|res| res)
                .flatten()
                .collect::<Vec<_>>();
            // fetch ns asn
            let asn = find_asn(&ns_ips, ip2asn_map);

            let ip_records = match ns_ips.is_empty() {
                true => None,
                false => Some(ns_ips),
            };

            Some(NameServer {
                names: ns_records,
                ips: ip_records,
                asn,
            })
        }
        Err(_) => None,
    }
}

pub async fn query_cname<T: ConnectionProvider>(
    target: &str,
    resolver: &Resolver<T>,
) -> Option<Vec<String>> {
    let lookup_cname_future = resolver.lookup(target, RecordType::CNAME);
    match lookup_cname_future.await {
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

pub async fn query_ipv6<T: ConnectionProvider>(
    target: &str,
    resolver: &Resolver<T>,
) -> Option<Vec<IpAddr>> {
    let lookup_aaaa_future = resolver.ipv6_lookup(target);
    match lookup_aaaa_future.await {
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

pub async fn query_ipv4<T: ConnectionProvider>(
    target: &str,
    resolver: &Resolver<T>,
) -> Option<Vec<IpAddr>> {
    let lookup_a_future = resolver.ipv4_lookup(target);
    match lookup_a_future.await {
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

pub async fn query_ipv4_ipv6<T: ConnectionProvider>(
    target: &str,
    resolver: &Resolver<T>,
) -> Option<Vec<IpAddr>> {
    let ipv4 = query_ipv4(target, resolver);
    let ipv6 = query_ipv6(target, resolver);
    let mut ip: Vec<IpAddr> = Vec::new();
    if let Some(v4) = ipv4.await {
        ip.extend(v4);
    }
    if let Some(v6) = ipv6.await {
        ip.extend(v6);
    }
    if ip.is_empty() { None } else { Some(ip) }
}

// #[cfg(test)]
// mod tests {
//     use super::*;
//     use hickory_resolver::Resolver;
//     use ip2asn::Builder;
//     use std::{
//         net::{IpAddr, Ipv4Addr, Ipv6Addr},
//         vec,
//     };
//     use tokio::runtime::Runtime;
//     #[test]
//     fn test_query_ipv4() {
//         let target = "localhost";
//         let io_loop = Runtime::new().unwrap();
//         // Use the host OS'es `/etc/resolv.conf`
//         let resolver = Resolver::builder_tokio().unwrap().build();
//         let response = query_ipv4(target, &resolver);

//         // check response
//         assert!(response.is_some());
//         let mut response = response.unwrap();
//         // localhost should only resolve to 127.0.0.1
//         let expected = vec![IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))];
//         for ip in &mut response {
//             assert!(expected.contains(ip));
//         }
//     }

//     #[test]
//     fn test_query_ipv6() {
//         let target = "localhost";
//         let io_loop = Runtime::new().unwrap();
//         // Use the host OS'es `/etc/resolv.conf`
//         let resolver = Resolver::builder_tokio().unwrap().build();
//         let response = query_ipv6(target, &io_loop, &resolver);

//         // check response
//         assert!(response.is_some());
//         let mut response = response.unwrap();
//         // localhost should only resolve to ::1
//         let expected = vec![IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1))];
//         for ip in &mut response {
//             assert!(expected.contains(ip));
//         }
//     }

//     #[test]
//     fn test_query_ipv4_ipv6() {
//         let target = "localhost";
//         let io_loop = Runtime::new().unwrap();
//         // Use the host OS'es `/etc/resolv.conf`
//         let resolver = Resolver::builder_tokio().unwrap().build();
//         let response = query_ipv4_ipv6(target, &io_loop, &resolver);

//         // check response
//         assert!(response.is_some());
//         let mut response = response.unwrap();
//         // localhost should only resolve to 127.0.0.1 and ::1
//         let expected = vec![
//             IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
//             IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)),
//         ];
//         for ip in &mut response {
//             assert!(expected.contains(ip));
//         }
//     }

//     #[test]
//     fn test_query_cname() {
//         let target = "www.example.com";
//         let io_loop = Runtime::new().unwrap();
//         // Use the host OS'es `/etc/resolv.conf`
//         let resolver = Resolver::builder_tokio().unwrap().build();
//         let response = query_cname(target, &resolver);

//         // check response
//         assert!(response.is_some());
//         let mut response = response.unwrap();

//         // www.example.com should resolve to www.example.com-v4.edgesuite.net.
//         let expected = vec!["www.example.com-v4.edgesuite.net.".to_string()];
//         for cname in &mut response {
//             assert!(expected.contains(cname));
//         }
//     }
//     #[test]
//     fn test_query_ns() {
//         let target = "facebook.com";
//         let io_loop = Runtime::new().unwrap();
//         // Use the host OS'es `/etc/resolv.conf`
//         let resolver = Resolver::builder_tokio().unwrap().build();
//         // A small, in-memory TSV data source for the example.
//         let data = "129.134.0.0\t129.134.255.255\t32934\tUS\tFACEBOOK-AS";

//         // Build the map from a source that implements `io::Read`.
//         let ip2asn_map = Builder::new()
//             .with_source(data.as_bytes())
//             .unwrap()
//             .build()
//             .unwrap();

//         let response = query_ns(target, &io_loop, &resolver, &ip2asn_map);
//         // check response
//         assert!(response.is_some());
//         let response = response.unwrap();
//         // facebook.com should resolve to a set of known NS
//         let expected_names = vec![
//             "a.ns.facebook.com.".to_string(),
//             "b.ns.facebook.com.".to_string(),
//             "c.ns.facebook.com.".to_string(),
//             "d.ns.facebook.com.".to_string(),
//         ];
//         for name in &response.names {
//             assert!(expected_names.contains(name));
//         }
//         assert!(response.ips.is_some());
//         let ips = response.ips.unwrap();
//         assert_eq!(ips.len(), 8);
//     }
// }
