#[macro_use]
extern crate serde_derive;
extern crate cert_machine;
extern crate openssl;

mod config_parser;

use config_parser::Config;
use cert_machine::{CertificateParameters, Subject};
use cert_machine::gen_cert;
use openssl::x509::X509;
use openssl::pkey::PKey;
use std::fs;

fn opt_str(opt_string: &Option<String>) -> Option<&str> {
    match opt_string {
        Some(s) => Some(s.as_ref()),
        None => None,
    }
}

fn main() {
        let config = Config::new("config.toml");
    {
        let ca_subject = Subject {
            common_name: &config.cluster_name,
            country: opt_str(&config.ca.country),
            organization: opt_str(&config.ca.organization),
            organization_unit: opt_str(&config.ca.organization_unit),
            state_or_province_name: opt_str(&config.ca.state_or_province_name),
            locality: opt_str(&config.ca.locality),
        };

        let ca_cert = CertificateParameters {
            key_length: config.ca.key_size,
            serial_number: 1,
            validity_days: config.ca.validity_days,
            subject: &ca_subject,
            key_usage: vec![
                "digital_signature".to_owned(),
                "key_encipherment".to_owned(),
                "key_cert_sign".to_owned(),
                "critical".to_owned(),
            ],
            extended_key_usage: None,
            basic_constraints: Some(vec![
                "ca".to_owned(),
                ]),
            san: None,
            is_self_signed: true,
            ca_key: None,
            ca_crt: None,
            filename: "ca",
        };

        println!("Creating CA with name: {}", config.cluster_name);
        gen_cert(&ca_cert);
    }

    let ca_key_file = fs::read("certs/ca.key").expect("Unable to open ca.key");
    let ca_key = PKey::private_key_from_pem(&ca_key_file).expect("Unable to parse ca.key");

    let ca_cert_file = fs::read("certs/ca.crt").expect("Unable to open ca.crt");
    let ca_cert = X509::from_pem(&ca_cert_file).expect("Unable to parse ca.crt");

    for worker in config.worker {
        println!("Creating cert for node: {}", worker.hostname);

        let cert_filename = if let Some(filename) = worker.filename {
            filename
        } else {
            worker.hostname.clone()
        };

        let subject = Subject {
            common_name: &format!("system:node:{}", &worker.hostname),
            country: None,
            organization: Some("system:nodes"),
            organization_unit: None,
            state_or_province_name: None,
            locality: None,
        };

        let cert = CertificateParameters {
            key_length: 2048,
            serial_number: 5678,
            validity_days: 100,
            subject: &subject,
            key_usage: vec![
                "digital_signature".to_owned(),
                "key_encipherment".to_owned(),
                "critical".to_owned(),
            ],
            extended_key_usage: Some(vec!["server_auth".to_owned()]),
            basic_constraints: None,
            // san: Some(vec![
            //     "kubernetes".to_owned(),
            //     "kubernetes.default".to_owned(),
            //     "kubernetes.default".to_owned(),
            //     "kubernetes.default.svc.cluster.local".to_owned(),
            //     "10.96.0.1".to_owned(),
            // ]),

            san: Some(worker.san),
            is_self_signed: false,
            ca_key: Some(&ca_key),
            ca_crt: Some(&ca_cert),
            filename: &cert_filename,
        };

        gen_cert(&cert);
    }
}
