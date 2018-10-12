extern crate cert_machine;
extern crate openssl;

use cert_machine::{CertificateParameters, Subject};
use cert_machine::gen_cert;
use openssl::x509::X509;
use openssl::pkey::PKey;
use std::fs;

fn main() {
    let ca_subject = Subject {
        common_name: "Kubernetes CA".to_owned(),
        country: Some("LV".to_owned()),
        organization: Some("Containerum".to_owned()),
        organization_unit: Some("IFR".to_owned()),
        state_or_province_name: None,
        locality: None,
    };

    let ca_cert = CertificateParameters {
        key_length: 2048,
        serial_number: 1,
        validity_days: 1000,
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
        filename: "ca".to_owned(),
    };

    gen_cert(&ca_cert);

    let ca_key_file = fs::read("ca.key").expect("Unable to open ca.key");
    let ca_key = PKey::private_key_from_pem(&ca_key_file).expect("Unable to parse ca.key");

    let ca_cert_file = fs::read("ca.crt").expect("Unable to open ca.crt");
    let ca_cert = X509::from_pem(&ca_cert_file).expect("Unable to parse ca.crt");

    let subject = Subject {
        common_name: "kubernetes".to_owned(),
        country: None,
        organization: None,
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
        san: Some(vec![
            "kubernetes".to_owned(),
            "kubernetes.default".to_owned(),
            "kubernetes.default".to_owned(),
            "kubernetes.default.svc.cluster.local".to_owned(),
            "10.96.0.1".to_owned(),
        ]),
        is_self_signed: false,
        ca_key: Some(&ca_key),
        ca_crt: Some(&ca_cert),
        filename: "cert".to_owned(),
    };

    gen_cert(&cert);
}
