use anyhow::Result;
use hickory_resolver::{Resolver, config::ResolverConfig, name_server::TokioConnectionProvider};
use ip2asn::{Builder, IpAsnMap};
use std::{env, fs::File, io, path::Path};

fn is_tmp_file_exists(filename: &str) -> bool {
    let dir = env::temp_dir();
    Path::new(dir.join(filename).as_os_str()).exists()
}

fn fetch_and_save_asn_db(url: &str, path: &Path) -> Result<()> {
    let mut response = reqwest::blocking::get(url)?;
    let mut dest = File::create(path)?;
    io::copy(&mut response, &mut dest)
        .map_err(|e| anyhow::anyhow!("Failed to save ASN database: {}", e))?;
    println!("Downloaded ASN database to {}", path.display());
    Ok(())
}

pub fn open_asn_db() -> Result<IpAsnMap> {
    let filename = "ip2asn-combined.tsv.gz";
    let url = "https://iptoasn.com/data/ip2asn-combined.tsv.gz";
    let dir = env::temp_dir();
    let path = dir.join(filename);

    if !is_tmp_file_exists(filename) {
        fetch_and_save_asn_db(url, &path).map_err(|e| {
            anyhow::anyhow!(
                "Failed to fetch ASN database from {}: {}",
                url,
                e.to_string()
            )
        })?;
        println!("ASN database fetched successfully.");
    }
    println!("Loading ASN database from {}", path.display());
    let ipasn = Builder::new().from_path(path)?.build()?;
    Ok(ipasn)
}

pub fn get_resolver() -> Resolver<TokioConnectionProvider> {
    Resolver::builder_with_config(
        ResolverConfig::cloudflare(),
        TokioConnectionProvider::default(),
    )
    .build()
}

/// Break an iterator into chunks of a specified size
/// https://users.rust-lang.org/t/how-to-breakup-an-iterator-into-chunks/87915/5
/// This function returns an iterator that yields vectors of items, each of size `chunk_size`.
/// The last chunk may be smaller if there are not enough items left.
pub fn chunked<I>(
    a: impl IntoIterator<Item = I>,
    chunk_size: usize,
) -> impl Iterator<Item = Vec<I>> {
    let mut a = a.into_iter();
    std::iter::from_fn(move || {
        Some(a.by_ref().take(chunk_size).collect()).filter(|chunk: &Vec<_>| !chunk.is_empty())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chunked() {
        let data = vec![1, 2, 3, 4, 5, 6, 7];
        let chunk_size = 3;
        let chunks: Vec<Vec<i32>> = chunked(data, chunk_size).collect();
        assert_eq!(chunks, vec![vec![1, 2, 3], vec![4, 5, 6], vec![7]]);
    }

    #[test]
    fn test_open_asn_db() {
        let result_fetch = open_asn_db();
        assert!(result_fetch.is_ok());
        // test if the temp file exists
        let result_tmp = open_asn_db();
        assert!(result_tmp.is_ok());
    }
}
