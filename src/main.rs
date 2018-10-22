#[macro_use]
extern crate serde_derive;
extern crate cert_machine;
extern crate openssl;

mod config_parser;
mod kubernetes_certs;

use config_parser::Config;
use openssl::pkey::PKey;
use std::process::exit;
use std::fs;

fn main() {
    let config = Config::new("config.toml");
    let out_dir = "certs".to_owned();

    println!("Creating output dirs.");
    let etcd_dir = format!("{}/etcd", out_dir);
    match fs::create_dir_all(etcd_dir) {
        Ok(_) => (),
        Err(e) => {
            println!("Error when creating dir: {:#?}", e);
            exit(1);
        }
    }


    let (ca_cert, ca_key) = match kubernetes_certs::gen_main_ca_cert(&config) {
        Ok(bundle) => {
            kubernetes_certs::write_bundle_to_file(&bundle, &out_dir, "ca");
            bundle
        },
        Err(error) => {
            eprintln!("{}", error);
            return
        }
    };
    let ca_key = PKey::private_key_from_pem(&ca_key).unwrap();

    for instance in config.worker.iter() {
        kubernetes_certs::gen_kubelet_cert(&instance, &ca_key, &ca_cert);
    }

    match kubernetes_certs::gen_ca_cert("etcd", Some((&ca_key, &ca_cert))) {
        Ok(bundle) => {
            kubernetes_certs::write_bundle_to_file(&bundle,  &out_dir,"etcd/etcd-ca");
            bundle
        },
        Err(error) => {
            eprintln!("{}", error);
            return
        }
    };

    let (etcd_ca_cert, etcd_ca_key) = match kubernetes_certs::gen_ca_cert("etcd", Some((&ca_key, &ca_cert))) {
        Ok(bundle) => {
            kubernetes_certs::write_bundle_to_file(&bundle, &out_dir, "etcd/etcd-ca");
            bundle
        },
        Err(error) => {
            eprintln!("{}", error);
            return
        }
    };
    let etcd_ca_key = PKey::private_key_from_pem(&etcd_ca_key).unwrap();

    for instance in config.etcd_server.iter() {
        kubernetes_certs::gen_etcd_cert(&instance, &etcd_ca_key, &etcd_ca_cert);
    }

    kubernetes_certs::kube_certs(&ca_key, &ca_cert, &config, &out_dir);
}


//    let ca_key_file = fs::read("certs/ca.key").expect("Unable to open ca.key");
//    let ca_key = PKey::private_key_from_pem(&ca_key_file).expect("Unable to parse ca.key");
//
//    let ca_cert_file = fs::read("certs/ca.crt").expect("Unable to open ca.crt");
//    let ca_cert = X509::from_pem(&ca_cert_file).expect("Unable to parse ca.crt");