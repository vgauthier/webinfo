use anyhow::Result;
use clap::Parser;
use std::fs::File;
use std::path::PathBuf;
use tokio::runtime::Runtime;
use webinfo::{
    CsvRecord, query,
    utils::{get_resolver, open_asn_db},
};

#[derive(Parser)]
#[command(version, about, long_about = None, author = "Vincent Gauthier <vg@luxbulb.org>")]
struct Cli {
    /// Input CSV file path
    #[arg(short, long)]
    csv: PathBuf,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let csv_path = cli.csv;
    let map_ip_asn = open_asn_db()?;
    let io_loop = Runtime::new()?;
    let resolver = get_resolver();
    let file =
        File::open(csv_path).map_err(|e| anyhow::anyhow!("Failed to open CSV file: {}", e))?;
    let mut rdr = csv::Reader::from_reader(file);
    for result in rdr.deserialize() {
        let record: CsvRecord = result?;
        let ip_info = query(record, &io_loop, &resolver, &map_ip_asn)?;
        println!("IP Info: {:?}", ip_info);
    }
    Ok(())
}
