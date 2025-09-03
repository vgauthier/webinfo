use anyhow::Result;
use clap::Parser;
use std::path::PathBuf;
use tokio::runtime::Runtime;
use webinfo::{
    query,
    utils::{get_resolver, open_asn_db},
};

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    /// Input TSV file path
    #[arg(short, long)]
    tsv: PathBuf,
}

fn main() -> Result<()> {
    //let cli = Cli::parse();
    //let _tsv_path = cli.tsv;
    let map_ip_asn = open_asn_db()?;
    let io_loop = Runtime::new()?;
    let resolver = get_resolver();

    let ip_info = query("https://www.veepee.fr/", &io_loop, &resolver, &map_ip_asn)?;
    println!("IP Info: {:?}", ip_info);
    Ok(())
}
