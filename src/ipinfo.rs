use super::{asn, asn::Asn, dns, tls};
use anyhow::Result;
use hickory_resolver::{Resolver, name_server::ConnectionProvider};
use ip2asn::IpAsnMap;
use serde::{Deserialize, Serialize};
use std::{net::IpAddr, sync::Arc};
use url::Url;

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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
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

// Implement a method to create IpInfo from OriginRecord
impl IpInfo {
    pub async fn from_record<T: ConnectionProvider>(
        target: OriginRecord,
        resolver: Resolver<T>,
        ip2asn_map: Arc<IpAsnMap>,
    ) -> Result<IpInfo> {
        // Parse Hostname
        let hostname = extract_hostname(&target.origin)
            .ok_or_else(|| anyhow::anyhow!("Invalid hostname: {}", target.origin))?;
        // extract TLD
        let domain = extract_domain(&hostname).ok();
        if domain.is_none() {
            eprintln!(
                "Warning: Could not extract domain from hostname: {}",
                hostname
            );
        }
        let ip = dns::query_ipv4_ipv6(&hostname, &resolver);
        let cname = dns::query_cname(&hostname, &resolver);
        let ns = match &domain {
            Some(domain) => dns::query_ns(domain, &resolver, &ip2asn_map).await,
            None => None,
        };
        let (ip, cname) = tokio::join!(ip, cname);
        let asn = if let Some(ips) = &ip {
            asn::lookup_ip(ips, &ip2asn_map)
        } else {
            None
        };
        let tls = tls::retrive_cert_info(&hostname).ok();
        Ok(IpInfo {
            origin: target.clone(),
            records: IpInfoRecord {
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
}

fn extract_hostname(url: &str) -> Option<String> {
    let parsed_url = Url::parse(url).ok();
    match parsed_url {
        Some(parsed_url) => Some(parsed_url.host_str()?.to_string()),
        None => None,
    }
}

fn extract_domain(url: &str) -> Result<String> {
    // Count the number of dots in the URL to handle single-label domains
    let ndots = url.chars().filter(|c| *c == '.').count();
    if ndots == 1 {
        return Ok(url.to_owned());
    }
    let domain = psl::domain_str(url)
        .ok_or_else(|| anyhow::anyhow!("Failed to parse domain from URL: {}", url))?;
    Ok(domain.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::open_asn_db;

    #[test]
    fn test_extract_hostname() {
        let url = "https://www.example.com/path?query=param";
        let hostname = extract_hostname(url);
        assert_eq!(hostname, Some("www.example.com".to_string()));
    }

    #[test]
    fn test_extract_domain() {
        let url = "www.example.co.uk";
        let domain = extract_domain(url).unwrap();
        assert_eq!(domain, "example.co.uk".to_string());

        let url = "carrd.co";
        let domain = extract_domain(url).unwrap();
        assert_eq!(domain, "carrd.co".to_string());
    }

    #[test]
    fn test_extract_domain_invalid() {
        let url = "invalid_domain";
        let domain = extract_domain(url);
        assert!(domain.is_err());
    }

    #[tokio::test]
    async fn test_from_record() {
        let origin = OriginRecord {
            origin: "https://www.example.com".to_string(),
            popularity: 100,
            date: "2023-10-01".to_string(),
            country: "US".to_string(),
        };
        // Use the host OS'es `/etc/resolv.conf`
        let resolver = Resolver::builder_tokio().unwrap().build();
        let ip2asn_map = open_asn_db().await.unwrap();
        let ip2asn_map = Arc::new(ip2asn_map);
        let ip_info = IpInfo::from_record(origin, resolver, ip2asn_map.clone()).await;
        assert!(ip_info.is_ok());
        let ip_info = ip_info.unwrap();
        assert_eq!(ip_info.records.hostname, "www.example.com");
        assert_eq!(ip_info.records.domain, "example.com".to_string().into());
    }
}
