mod dns;
mod tls;
pub mod utils;

use anyhow::Result;
use hickory_resolver::{Resolver, name_server::ConnectionProvider};
use ip_network::IpNetwork;
use ip2asn::IpAsnMap;
use serde::{Deserialize, Serialize};
use std::collections::hash_map::Entry::Vacant;
use std::{collections::HashMap, net::IpAddr};
use tldextract::TldOption;
use tokio::runtime::Runtime;
use url::Url;

#[derive(Deserialize, Serialize, Debug)]
#[allow(dead_code)]
pub struct CsvRecord {
    pub origin: String,
    pub popularity: u32,
    pub date: String,
    pub country: String,
}

#[derive(Serialize, Debug)]
pub struct Asn {
    pub network: Vec<IpNetwork>,
    pub asn: u32,
    pub organization: String,
    pub country_code: String,
}

#[derive(Serialize, Debug, Default)]
pub struct Record {
    pub hostname: String,
    pub domain: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cname: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ns: Option<dns::NameServer>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip: Option<Vec<IpAddr>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub asn: Option<Vec<Asn>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls: Option<tls::CertificateIssuerInfo>,
}

#[derive(Serialize, Debug)]
pub struct IpInfo {
    pub origin: CsvRecord,
    pub records: Record,
}

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

pub fn query<T: ConnectionProvider>(
    target: CsvRecord,
    io_loop: &Runtime,
    resolver: &Resolver<T>,
    ip2asn_map: &IpAsnMap,
) -> Result<IpInfo> {
    // Parse Hostname
    let hostname =
        extract_hostname(&target.origin).ok_or_else(|| anyhow::anyhow!("Invalid hostname"))?;
    // extract TLD
    let domain = extract_domain(&target.origin).ok_or_else(|| anyhow::anyhow!("Invalid domain"))?;
    let ip = dns::query_ipv4_ipv6(&hostname, io_loop, resolver);
    let cname = dns::query_cname(&hostname, io_loop, resolver);
    let ns = dns::query_ns(&domain, io_loop, resolver, ip2asn_map);
    let asn = if let Some(ips) = &ip {
        find_asn(ips, ip2asn_map)
    } else {
        None
    };
    let tls = tls::retrive_cert_info(&hostname).ok();
    Ok(IpInfo {
        origin: target,
        records: Record {
            hostname,
            domain,
            cname,
            ns,
            ip,
            asn,
            tls,
        },
    })
}
