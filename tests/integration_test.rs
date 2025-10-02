use assert_cmd::prelude::*; // Add methods on commands
use assert_fs::prelude::*; // Filesystem assertions
use predicates::prelude::*; // Used for writing assertions
use std::process::Command; // Run programs
#[test]
fn file_doesnt_exist() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::cargo_bin("webinfo")?;

    cmd.arg("--csv").arg("test/file/doesnt/exist");
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("Failed to open CSV file"));

    Ok(())
}

#[test]
fn process_csv_file() -> Result<(), Box<dyn std::error::Error>> {
    let file = assert_fs::NamedTempFile::new("sample.txt")?;
    file.write_str("origin,popularity,date,country\nhttps://www.free.fr,1000,2025-08-28,FR\n")?;

    let mut cmd = Command::cargo_bin("webinfo")?;
    cmd.arg("--csv").arg(file.path());
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("\"hostname\": \"www.free.fr\""));
    Ok(())
}

#[test]
fn process_csv_file_with_bad_hostname() -> Result<(), Box<dyn std::error::Error>> {
    let file = assert_fs::NamedTempFile::new("sample.txt")?;
    file.write_str("origin,popularity,date,country\nhttps://www.free.fr,1000,2025-08-28,FR\nhttps://www.example.toto,1000,2025-08-28,FR")?;

    let mut cmd = Command::cargo_bin("webinfo")?;
    cmd.arg("--csv").arg(file.path());
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("\"hostname\": \"www.free.fr\""));
    Ok(())
}

#[test]
fn process_csv_file_err() -> Result<(), Box<dyn std::error::Error>> {
    let file = assert_fs::NamedTempFile::new("sample.txt")?;
    file.write_str(
        "origin,popularity,date,country\nhttps://opco.uniformation.fr,1000,2025-08-28,FR\n",
    )?;

    let mut cmd = Command::cargo_bin("webinfo")?;
    cmd.arg("--csv").arg(file.path());
    cmd.assert().success().stdout(predicate::str::contains(
        "\"hostname\": \"opco.uniformation.fr\"",
    ));
    Ok(())
}
