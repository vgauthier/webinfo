use ip_network::IpNetwork;
use ip2asn::IpAsnMap;
use serde::Serialize;
use std::{
    collections::{HashMap, hash_map::Entry::Vacant},
    net::IpAddr,
    sync::Arc,
};

#[derive(Serialize, Debug, Clone)]
pub struct Asn {
    pub network: Vec<IpNetwork>,
    pub asn: u32,
    pub organization: String,
    pub country_code: String,
}

impl Asn {
    pub fn from_ip(ip: &IpAddr, ip2asn_map: &IpAsnMap) -> Option<Asn> {
        if let Some(asn_info) = ip2asn_map.lookup_owned(*ip) {
            Some(Asn {
                network: vec![asn_info.network],
                asn: asn_info.asn,
                organization: asn_info.organization.clone(),
                country_code: asn_info.country_code.clone(),
            })
        } else {
            None
        }
    }
}

fn update_asn_network(asn: &mut Asn, new_network: IpNetwork) {
    if !asn.network.contains(&new_network) {
        asn.network.push(new_network);
    }
}

/// Update the ASN information in the hash map
/// If the ASN already exists, update its networks; otherwise, insert it.
/// This function ensures that each ASN entry in the hash map has a unique set of networks.
fn update_asn(hash: &mut HashMap<u32, Asn>, new_asn: Asn) {
    if let Vacant(e) = hash.entry(new_asn.asn) {
        e.insert(new_asn);
    } else if let Some(existing_asn) = hash.get_mut(&new_asn.asn) {
        for network in new_asn.network {
            update_asn_network(existing_asn, network);
        }
    }
}

/// Find ASN information for a list of IP addresses
/// This function looks up each IP address in the provided ASN map and collects unique ASN information.
pub fn lookup_ip(ips: &Vec<IpAddr>, ip2asn_map: &Arc<IpAsnMap>) -> Option<Vec<Asn>> {
    // Find the ASN for the given IP address
    let mut asn_hash: HashMap<u32, Asn> = HashMap::new();
    for ip in ips {
        if let Some(asn) = Asn::from_ip(ip, ip2asn_map) {
            update_asn(&mut asn_hash, asn);
        }
    }
    if asn_hash.is_empty() {
        None
    } else {
        Some(asn_hash.into_values().collect())
    }
}
