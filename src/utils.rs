use anyhow::Result;
use hickory_resolver::{Resolver, config::ResolverConfig, name_server::TokioConnectionProvider};
use ip2asn::{Builder, IpAsnMap};
use std::{env, fs::File, io, path::Path};

fn is_asn_file_exists() -> bool {
    let dir = env::temp_dir();
    Path::new(dir.join("ip2asn-combined.tsv.gz").as_os_str()).exists()
}

fn fetch_asn_db(url: &str) -> Result<()> {
    let dir = env::temp_dir();
    let mut response = reqwest::blocking::get(url)?;
    let mut dest = File::create(dir.join("ip2asn-combined.tsv.gz"))?;
    io::copy(&mut response, &mut dest)?;
    println!(
        "Downloaded ASN database to {}",
        dir.join("ip2asn-combined.tsv.gz").display()
    );
    Ok(())
}

pub fn open_asn_db() -> Result<IpAsnMap> {
    let dir = env::temp_dir();
    if !is_asn_file_exists() {
        let url = "https://iptoasn.com/data/ip2asn-combined.tsv.gz";
        fetch_asn_db(url)?;
        println!("ASN database fetched successfully.");
    }
    println!(
        "Loading ASN database from {}",
        dir.join("ip2asn-combined.tsv.gz").display()
    );

    let ipasn = Builder::new()
        .from_path(dir.join("ip2asn-combined.tsv.gz"))?
        .build()?;

    Ok(ipasn)
}

pub fn get_resolver() -> Resolver<TokioConnectionProvider> {
    Resolver::builder_with_config(
        ResolverConfig::cloudflare(),
        TokioConnectionProvider::default(),
    )
    .build()
}
