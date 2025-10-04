use super::{asn, asn::Asn, dns, tls};
use anyhow::Result;
use hickory_resolver::{Resolver, name_server::ConnectionProvider};
use ip2asn::IpAsnMap;
use publicsuffix2::{List, MatchOpts, TypeFilter};
use serde::{Deserialize, Serialize};
use std::{net::IpAddr, sync::Arc};
use tracing::{Level, event};
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

//******************************************************************************
//
// Builder pattern for IpInfo
//
//******************************************************************************
#[derive(Debug)]
pub struct IpInfoRunner<T: ConnectionProvider> {
    origin: OriginRecord,
    resolver: Option<Resolver<T>>,
    ip2asn_map: Option<Arc<IpAsnMap>>,
    tls: bool,
}

impl<T: ConnectionProvider> IpInfoRunner<T> {
    pub fn with_resolver(mut self, resolver: Resolver<T>) -> Self {
        self.resolver = Some(resolver);
        self
    }

    pub fn with_ip2asn_map(mut self, ip2asn_map: Arc<IpAsnMap>) -> Self {
        self.ip2asn_map = Some(ip2asn_map);
        self
    }

    pub fn with_tls(mut self) -> Self {
        self.tls = true;
        self
    }

    pub async fn run(self) -> Result<IpInfo> {
        let mut ipinfo = IpInfo {
            origin: self.origin.clone(),
            records: IpInfoRecord::default(),
        };
        ipinfo.extract_hostname()?;

        // Perform DNS lookups with timeouts
        if self.resolver.is_some() {
            // IP lookup
            let ip =
                dns::query_ipv4_ipv6(&ipinfo.records.hostname, self.resolver.as_ref().unwrap());
            // CNAME lookup
            let cname = dns::query_cname(&ipinfo.records.hostname, self.resolver.as_ref().unwrap());
            let (ip, cname) = tokio::join!(ip, cname);
            ipinfo.records.ip = ip;
            ipinfo.records.cname = cname;
        }

        // ASN lookup
        if self.ip2asn_map.is_some() && ipinfo.records.ip.is_some() {
            ipinfo.records.asn = asn::lookup_ip(
                ipinfo.records.ip.as_ref().unwrap(),
                self.ip2asn_map.as_ref().unwrap(),
            );
        }
        // extract TLD
        ipinfo.records.domain = ipinfo.extract_domain();
        if ipinfo.records.domain.is_some() && self.resolver.is_some() && self.ip2asn_map.is_some() {
            // NS lookup
            ipinfo.records.ns = dns::query_ns(
                ipinfo.records.domain.as_ref().unwrap(),
                self.resolver.as_ref().unwrap(),
                self.ip2asn_map.as_ref().unwrap(),
            )
            .await;
        }

        // Retrieve TLS certificate info if the URL scheme is HTTPS
        if self.tls && ipinfo.origin.origin.contains("https://") && ipinfo.records.ip.is_some() {
            let tls_info =
                tls::retrive_cert_info(&ipinfo.records.hostname, ipinfo.records.ip.as_ref());
            match tls_info {
                Ok(tls_info) => ipinfo.records.tls = Some(tls_info),
                Err(e) => {
                    event!(
                        Level::ERROR,
                        "Failed to retrieve TLS info for {}: {}",
                        ipinfo.records.hostname,
                        e
                    );
                }
            }
        }
        Ok(ipinfo)
    }
}

//******************************************************************************
//
// IpInfo
//
//******************************************************************************
impl IpInfo {
    pub fn runner<T: ConnectionProvider>(origin: OriginRecord) -> IpInfoRunner<T> {
        IpInfoRunner {
            origin,
            resolver: None,
            ip2asn_map: None,
            tls: false,
        }
    }

    fn extract_hostname(&mut self) -> Result<()> {
        let match_opt = MatchOpts {
            strict: true,
            ..Default::default()
        };
        let list = List::default();
        let tld = list.tld(&self.origin.origin, match_opt);
        if tld.is_none() {
            return Err(anyhow::anyhow!(
                "Invalid TLD in URL: {}",
                &self.origin.origin
            ));
        }
        let parsed_url = Url::parse(&self.origin.origin).ok();
        match parsed_url {
            Some(parsed_url) => {
                self.records.hostname = parsed_url.host_str().unwrap_or("").to_string();
                Ok(())
            }
            None => Err(anyhow::anyhow!(
                "Failed to parse URL: {}",
                &self.origin.origin
            )),
        }
    }

    fn extract_domain(&mut self) -> Option<String> {
        // You can filter to only use ICANN section rules.
        let opts_icann_only = MatchOpts {
            types: TypeFilter::Icann,
            ..Default::default()
        };
        let list = List::default();
        let parts = list.split(&self.records.hostname, opts_icann_only);
        if let Some(parts) = parts {
            match parts.sll.as_deref() {
                None => {
                    event!(
                        Level::WARN,
                        "Warning: Could not parse domain from hostname: {}",
                        &self.records.hostname
                    );
                    None
                }
                Some(_) => parts.sld.as_deref().map(|s| s.to_string()),
            }
        } else {
            event!(
                Level::WARN,
                "Warning: Could not parse domain from hostname: {}",
                &self.records.hostname
            );
            None
        }
    }
}

//******************************************************************************
//
// Tests
//
//******************************************************************************
#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::open_asn_db;

    #[test]
    fn test_extract_hostname() {
        let mut ipinfo = IpInfo {
            origin: OriginRecord {
                origin: "https://www.example.com".to_string(),
                popularity: 100,
                date: "2023-10-01".to_string(),
                country: "US".to_string(),
            },
            records: IpInfoRecord::default(),
        };

        let _ = ipinfo.extract_hostname();
        assert_eq!(ipinfo.records.hostname, "www.example.com");
    }

    #[test]
    fn test_extract_hostname_invalid() {
        let mut ipinfo = IpInfo {
            origin: OriginRecord {
                origin: "https://www.example.toto".to_string(),
                popularity: 100,
                date: "2023-10-01".to_string(),
                country: "US".to_string(),
            },
            records: IpInfoRecord::default(),
        };

        let hostname_result = ipinfo.extract_hostname();
        assert!(hostname_result.is_err());
    }

    #[test]
    fn test_extract_domain() {
        let urls = [
            "www.example.co.uk",
            "carrd.co",
            "phpmyadmin.hosting.ovh.net",
            "s3.amazonaws.com",
            "senpai-stream.cam",
        ];
        let expected_domains = [
            "example.co.uk",
            "carrd.co",
            "ovh.net",
            "amazonaws.com",
            "senpai-stream.cam",
        ];
        for (url, expected) in urls.iter().zip(expected_domains.iter()) {
            let mut ipinfo = IpInfo {
                origin: OriginRecord {
                    origin: url.to_string(),
                    popularity: 100,
                    date: "2023-10-01".to_string(),
                    country: "US".to_string(),
                },
                records: IpInfoRecord {
                    hostname: url.to_string(),
                    ..Default::default()
                },
            };
            let domain = ipinfo.extract_domain();
            assert!(domain.is_some());
            assert_eq!(domain.unwrap(), expected.to_string());
        }
    }

    #[test]
    fn test_extract_domain_invalid() {
        let bad_urls = ["invalid_domain", "https://www.example.toto"];
        for url in bad_urls {
            let mut ipinfo = IpInfo {
                origin: OriginRecord {
                    origin: url.to_string(),
                    popularity: 100,
                    date: "2023-10-01".to_string(),
                    country: "US".to_string(),
                },
                records: IpInfoRecord {
                    hostname: url.to_string(),
                    ..Default::default()
                },
            };
            let domain = ipinfo.extract_domain();
            assert!(domain.is_none());
        }
    }

    #[tokio::test]
    async fn test_builder_hostname_domaine() {
        let origin = OriginRecord {
            origin: "https://www.example.com".to_string(),
            popularity: 100,
            date: "2023-10-01".to_string(),
            country: "US".to_string(),
        };
        // Use the host OS'es `/etc/resolv.conf`
        let resolver = Resolver::builder_tokio().unwrap().build();
        let ip_info = IpInfo::runner(origin).with_resolver(resolver).run().await;
        assert!(ip_info.is_ok());
        let ip_info = ip_info.unwrap();
        assert_eq!(ip_info.records.hostname, "www.example.com");
        assert_eq!(ip_info.records.domain, "example.com".to_string().into());
    }

    #[tokio::test]
    async fn test_builder_with_bad_hostname() {
        let origin = OriginRecord {
            origin: "https://www.example.toto".to_string(),
            popularity: 100,
            date: "2023-10-01".to_string(),
            country: "US".to_string(),
        };
        // Use the host OS'es `/etc/resolv.conf`
        let resolver = Resolver::builder_tokio().unwrap().build();
        let ip_info_result = IpInfo::runner(origin).with_resolver(resolver).run().await;
        assert!(ip_info_result.is_err());
    }

    #[tokio::test]
    async fn test_builder() {
        let origin = OriginRecord {
            origin: "https://www.example.com".to_string(),
            popularity: 100,
            date: "2023-10-01".to_string(),
            country: "US".to_string(),
        };
        // Use the host OS'es `/etc/resolv.conf`
        let ip2asn_map = open_asn_db().await.unwrap();
        let ip2asn_map = Arc::new(ip2asn_map);
        let resolver = Resolver::builder_tokio().unwrap().build();
        let ip_info = IpInfo::runner(origin)
            .with_resolver(resolver)
            .with_ip2asn_map(ip2asn_map)
            .with_tls()
            .run()
            .await;
        assert!(ip_info.is_ok());
        let ip_info = ip_info.unwrap();
        assert_eq!(ip_info.records.hostname, "www.example.com");
        assert_eq!(ip_info.records.domain, "example.com".to_string().into());
        assert!(ip_info.records.ip.is_some());
        assert!(ip_info.records.cname.is_some());
        assert!(ip_info.records.tls.is_some());
    }
}
