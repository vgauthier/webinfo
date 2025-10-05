[![Rust CI](https://github.com/vgauthier/webinfo/actions/workflows/ci.yml/badge.svg)](https://github.com/vgauthier/webinfo/actions/workflows/ci.yml)
[![codecov](https://codecov.io/github/vgauthier/webinfo/graph/badge.svg?token=l1QTyO4xjx)](https://codecov.io/github/vgauthier/webinfo)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

# Webinfo

Retrive information about a given webserser 

## Usage

```sh
webinfo --csv input.csv > data.json
```

```sh
webinfo -- help
A tool to gather information about a list of websites.

Usage: webinfo [OPTIONS] --csv <CSV>

Options:
  -c, --csv <CSV>          Input CSV file path
  -s, --size <CHUNK_SIZE>  Number of concurrent tasks to run [default: 5]
  -d, --dns <DNS>          Custom DNS server IP addresses (comma-separated)
  -l, --logfile <LOGFILE>  Log file path [default: ./webinfo.log]
  -o, --output <OUTPUT>    Optional output file path (if not provided, output to stdout)
  -h, --help               Print help
  -V, --version            Print version
```


## Todo 
* Fetch info about MX
* read from gzip file
* ~~add option to create a ip list of-- dns server~~
* ~~clean code~~ 
* ~~Fix issue with tls~~
* ~~print json output to stdout~~
* ~~add concurency~~
* ~~Add option to commande line (logs)~~
* ~~Cleanup the main~~ 
* Add more tests

## License
This project is licensed under the Apache License Version 2.0.