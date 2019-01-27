extern crate toml;

use std::fs::File;
use std::io::prelude::*;
use std::path::Path;
use std::process::exit;

#[derive(Deserialize)]
pub struct Config {
    pub cluster_name: String,
    pub worker: Vec<Instance>,
    pub etcd_server: Vec<Instance>,
    pub user: Option<Vec<User>>,
    pub etcd_users: Option<Vec<String>>,
    pub validity_days: u32,
    #[serde(default = "cert_key_size")]
    pub key_size: u32,
    pub ca: Ca,
    pub master_san: Vec<String>,
    pub apiserver_internal_address: String,
    pub apiserver_external_address: String,
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
pub struct User {
    pub username: String,
    pub group: Option<String>,
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
        if !Path::new(&filename).exists() {
        	eprintln!("{} does not exists!", &filename);
        	exit(1);
        }
        let mut config_file = File::open(filename).unwrap();
        let mut contents = String::new();

        config_file.read_to_string(&mut contents).unwrap();

        let config: Config = match toml::from_str(&contents) {
        	Err(err) => {
        		eprintln!("Config parse error: {}", err);
        		exit(1);
        	},
        	Ok(config) => config,
        };

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
