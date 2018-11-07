extern crate toml;

use std::fs::File;
use std::io::prelude::*;

#[derive(Deserialize)]
pub struct Config {
    pub cluster_name: String,
    pub worker: Vec<Instance>,
    pub etcd_server: Vec<Instance>,
    pub validity_days: u32,
    #[serde(default = "cert_key_size")]
    pub key_size: u32,
    pub ca: Ca,
    pub master_san: Vec<String>,
    #[serde(default = "overwrite_false")]
    pub overwrite: bool,
    #[serde(default = "out_dir")]
    pub out_dir: String,
}

#[derive(Deserialize)]
pub struct Instance {
    pub filename: Option<String>,
    pub hostname: String,
    pub san: Vec<String>,
}

#[derive(Deserialize)]
pub struct Ca {
    pub country: Option<String>,
    pub organization: Option<String>,
    pub organization_unit: Option<String>,
    pub locality: Option<String>,
    pub state_or_province_name:Option<String>,
    pub validity_days: u32,
    #[serde(default = "ca_key_size")]
    pub key_size: u32,
}

impl Config {
    pub fn new(filename: &str) -> Box<Config> {
        let mut config_file = File::open(filename).unwrap();
        let mut contents = String::new();

        config_file.read_to_string(&mut contents).unwrap();

        let config: Config = toml::from_str(&contents).unwrap();

        Box::new(config)
    }
}

fn cert_key_size() -> u32 {
    2048
}

fn ca_key_size() -> u32 {
    4096
}

fn overwrite_false() -> bool {
    false
}

fn out_dir() -> String {
    "certs".to_owned()
}
