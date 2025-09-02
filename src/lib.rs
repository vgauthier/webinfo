mod dns;
mod tls;
pub mod utils;

use anyhow::Result;
use hickory_resolver::{Resolver, name_server::ConnectionProvider};
use ip_network::IpNetwork;
use ip2asn::IpAsnMap;
use serde::Serialize;
use std::collections::hash_map::Entry::Vacant;
use std::{collections::HashMap, net::IpAddr};
use tokio::runtime::Runtime;

#[derive(Serialize, Debug)]
pub struct Asn {
    pub network: Vec<IpNetwork>,
    pub asn: u32,
    pub organization: String,
    pub country_code: String,
}

#[derive(Serialize, Debug)]
pub struct Record {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cname: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip: Option<Vec<IpAddr>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub asn: Option<Vec<Asn>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls: Option<tls::CertificateIssuerInfo>,
}

#[derive(Serialize, Debug)]
pub struct IpInfo {
    pub host: String,
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

fn find_asn(ips: &Vec<IpAddr>, ip2asn_map: &IpAsnMap) -> Option<Vec<Asn>> {
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
    target: &str,
    io_loop: &Runtime,
    resolver: &Resolver<T>,
    ip2asn_map: &IpAsnMap,
) -> Result<IpInfo> {
    let ip = dns::query_ipv4_ipv6(target, io_loop, resolver);
    let cname = dns::query_cname(target, io_loop, resolver);
    let asn = if let Some(ips) = &ip {
        find_asn(ips, ip2asn_map)
    } else {
        None
    };
    let tls = tls::retrive_cert_info(target).ok();
    Ok(IpInfo {
        host: target.to_string(),
        records: Record {
            cname,
            ip,
            asn,
            tls,
        },
    })
}
