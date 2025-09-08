pub mod dns;
pub mod model;
pub mod tls;
pub mod utils;

use anyhow::Result;
use hickory_resolver::{Resolver, name_server::ConnectionProvider};
use ip_network::IpNetwork;
use ip2asn::IpAsnMap;
pub use model::*;
use std::collections::hash_map::Entry::Vacant;
use std::{collections::HashMap, net::IpAddr};
use tldextract::TldOption;
use url::Url;

fn update_asn(hash: &mut HashMap<u32, Asn>, new_asn: Asn) {
    if let Vacant(e) = hash.entry(new_asn.asn) {
        e.insert(new_asn);
    } else if let Some(existing_asn) = hash.get_mut(&new_asn.asn) {
        for network in new_asn.network {
            update_asn_network(existing_asn, network);
        }
    }
}

fn update_asn_network(asn: &mut Asn, new_network: IpNetwork) {
    if !asn.network.contains(&new_network) {
        asn.network.push(new_network);
    }
}

fn extract_hostname(url: &str) -> Option<String> {
    let parsed_url = Url::parse(url).ok();
    match parsed_url {
        Some(parsed_url) => Some(parsed_url.host_str()?.to_string()),
        None => None,
    }
}

fn extract_domain(url: &str) -> Option<String> {
    let ext = TldOption::default().cache_path(".tld_cache").build();
    match ext.extract(url) {
        Ok(extracted) => {
            if extracted.domain.is_none() || extracted.suffix.is_none() {
                return None;
            }
            let tld = format!(
                "{}.{}",
                extracted.domain.unwrap(),
                extracted.suffix.unwrap()
            );
            Some(tld)
        }
        Err(_) => None,
    }
}

pub fn find_asn(ips: &Vec<IpAddr>, ip2asn_map: &IpAsnMap) -> Option<Vec<Asn>> {
    // Find the ASN for the given IP address
    let mut asn_hash: HashMap<u32, Asn> = HashMap::new();
    for ip in ips {
        if let Some(a) = ip2asn_map.lookup(*ip) {
            let asn = Asn {
                network: vec![a.network],
                asn: a.asn,
                organization: a.organization.into(),
                country_code: a.country_code.into(),
            };
            update_asn(&mut asn_hash, asn);
        }
    }
    if asn_hash.is_empty() {
        None
    } else {
        Some(asn_hash.into_values().collect())
    }
}

pub async fn query<T: ConnectionProvider>(
    target: OriginRecord,
    resolver: Resolver<T>,
) -> Result<IpInfo> {
    // Parse Hostname
    let hostname =
        extract_hostname(&target.origin).ok_or_else(|| anyhow::anyhow!("Invalid hostname"))?;
    // extract TLD
    let domain = extract_domain(&target.origin).ok_or_else(|| anyhow::anyhow!("Invalid domain"))?;
    let ip = dns::query_ipv4_ipv6(&hostname, &resolver);
    let cname = dns::query_cname(&hostname, &resolver);
    //let ns = dns::query_ns(&domain, &resolver, ip2asn_map);
    let (ip, cname) = tokio::join!(ip, cname);
    // let asn = if let Some(ips) = &ip {
    //     find_asn(ips, ip2asn_map)
    // } else {
    //     None
    // };
    let tls = tls::retrive_cert_info(&hostname).ok();
    Ok(IpInfo {
        origin: target,
        records: IpInfoRecord {
            hostname,
            domain,
            cname,
            ns: None,
            ip,
            asn: None, //asn,
            tls,
        },
    })
}
