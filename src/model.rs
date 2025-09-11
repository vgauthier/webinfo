use super::{asn::Asn, dns, tls};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

#[derive(Deserialize, Serialize, Debug, Clone)]
#[allow(dead_code)]
pub struct OriginRecord {
    pub origin: String,
    pub popularity: u32,
    pub date: String,
    pub country: String,
}

#[derive(Serialize, Debug, Default)]
pub struct IpInfoRecord {
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
    pub origin: OriginRecord,
    pub records: IpInfoRecord,
}
