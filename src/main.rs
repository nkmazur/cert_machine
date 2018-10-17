#[macro_use]
extern crate serde_derive;
extern crate cert_machine;
extern crate openssl;

mod config_parser;
mod kubernetes_certs;

use config_parser::Config;
use openssl::x509::X509;
use openssl::pkey::PKey;
use std::fs;

fn main() {
    let config = Config::new("config.toml");

    kubernetes_certs::gen_ca_cert(&config);

    let ca_key_file = fs::read("certs/ca.key").expect("Unable to open ca.key");
    let ca_key = PKey::private_key_from_pem(&ca_key_file).expect("Unable to parse ca.key");

    let ca_cert_file = fs::read("certs/ca.crt").expect("Unable to open ca.crt");
    let ca_cert = X509::from_pem(&ca_cert_file).expect("Unable to parse ca.crt");

    for instance in config.worker.iter() {
        kubernetes_certs::gen_kubelet_cert(&instance, &ca_key, &ca_cert);
    }

    for instance in config.etcd_server.iter() {
        kubernetes_certs::gen_etcd_cert(&instance, &ca_key, &ca_cert);
    }

    kubernetes_certs::kube_certs();
}
