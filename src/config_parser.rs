extern crate toml;

use std::fs::File;
use std::io::prelude::*;

#[derive(Debug)]
#[derive(Deserialize)]
pub struct Config {
    pub cluster_name: String,
    pub worker: Vec<Instance>,
    pub etcd_server: Vec<Instance>,
    pub validity_days: usize,
    pub key_size: u32,
    pub ca: Ca,
    pub master_san: Vec<String>
}

#[derive(Debug)]
#[derive(Deserialize)]
pub struct Instance {
    pub filename: Option<String>,
    pub hostname: String,
    pub san: Vec<String>,
}

#[derive(Debug)]
#[derive(Deserialize)]
pub struct Ca {
    pub country: Option<String>,
    pub organization: Option<String>,
    pub organization_unit: Option<String>,
    pub locality: Option<String>,
    pub state_or_province_name:Option<String>,
    pub validity_days: u32,
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
