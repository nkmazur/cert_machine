use openssl;
use config_parser::{Config, Instance};
use cert_machine::{CertificateParameters, Subject};

fn opt_str(opt_string: &Option<String>) -> Option<&str> {
    match opt_string {
        Some(s) => Some(s.as_ref()),
        None => None,
    }
}

pub fn gen_ca_cert(config: &Config) {
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
        subject: ca_subject,
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
    ca_cert.gen_cert();

}

pub fn gen_kubelet_cert(worker: &Instance, ca_key: &openssl::pkey::PKey<openssl::pkey::Private>, ca_cert: &openssl::x509::X509) {
    println!("Creating cert for node: {}", worker.hostname);

    let cert_filename = if let Some(ref filename) = worker.filename {
        filename.to_owned()
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
        subject: subject,
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

        san: Some(worker.san.iter().map(|s| s as &str).collect()),
        is_self_signed: false,
        ca_key: Some(&ca_key),
        ca_crt: Some(&ca_cert),
        filename: &cert_filename,
    };

    cert.gen_cert();
}

pub fn gen_etcd_cert(worker: &Instance, ca_key: &openssl::pkey::PKey<openssl::pkey::Private>, ca_cert: &openssl::x509::X509) {
    println!("Creating cert for etcd node: {}", worker.hostname);

    let cert_filename = if let Some(ref filename) = worker.filename {
        filename.to_owned()
    } else {
        worker.hostname.clone()
    };

    let subject = Subject {
        common_name: &worker.hostname,
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
        subject: subject,
        key_usage: vec![
            "digital_signature".to_owned(),
            "key_encipherment".to_owned(),
            "critical".to_owned(),
        ],
        extended_key_usage: Some(vec!["server_auth".to_owned()]),
        basic_constraints: None,

        san: Some(worker.san.iter().map(|s| s as &str).collect()),
        is_self_signed: false,
        ca_key: Some(&ca_key),
        ca_crt: Some(&ca_cert),
        filename: &cert_filename,
    };

    cert.gen_cert();
}

pub fn kube_certs() {
    // let v: Vec<(&str, &str)> = vec![
    // ("system:kube-controller-manager", "system:kube-controller-manager"),
    // ("system:kube-proxy" ,"system:node-proxier"),
    // ("system:kube-scheduler" ,"system:kube-scheduler"),
    // ("service-accounts" ,"Kubernetes,")];

    let mut sa = CertificateParameters::default("service-accounts");

    sa.subject.organization = Some("Kubernetes");
    sa.key_usage = vec![
            "digital_signature".to_owned(),
            "key_encipherment".to_owned(),
            "critical".to_owned(),
    ];
    sa.extended_key_usage = Some(vec![
        "server_auth".to_owned(),
        "client_auth".to_owned(),        
    ]);

    sa.gen_cert();
}
