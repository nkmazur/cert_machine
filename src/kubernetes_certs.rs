use std::fs;
use openssl::x509::X509;
use openssl::pkey::Private;
use openssl::pkey::PKey;
use config_parser::{Config, Instance};
use cert_machine::{CertificateParameters, Subject};

fn opt_str(opt_string: &Option<String>) -> Option<&str> {
    match opt_string {
        Some(s) => Some(s.as_ref()),
        None => None,
    }
}

pub fn write_bundle_to_file(bundle: &(X509, Vec<u8>), filename: &str) {
    let (certificate, key) = bundle;

    let pem = certificate.to_pem().unwrap();

    let crt_filename = format!("certs/{}.crt", &filename);
    let key_filename = format!("certs/{}.key", &filename);

    fs::write(crt_filename, pem).expect("Unable to write file!");
    fs::write(key_filename, key).expect("Unable to write file!");
}

pub fn gen_main_ca_cert(config: &Config) {
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
            "digital_signature",
            "key_encipherment",
            "key_cert_sign",
            "critical",
        ],
        extended_key_usage: None,
        basic_constraints: Some(vec![
            "ca",
            ]),
        san: None,
        is_self_signed: true,
        ca_key: None,
        ca_crt: None,
    };

    println!("Creating CA with name: {}", config.cluster_name);
    let result = ca_cert.gen_cert();

    let (certificate, key) = match result {
        Ok(result) => result,
        Err(error) => {
            eprintln!("{}", error);
            return
        }
    };

    let pem = certificate.to_pem().unwrap();

    let crt_filename = format!("certs/ca.crt");
    let key_filename = format!("certs/ca.key");

    fs::write(crt_filename, pem).expect("Unable to write file!");
    fs::write(key_filename, key).expect("Unable to write file!");

}

pub fn gen_ca_cert(cn: &str, main_ca: Option<(&PKey<Private>, &X509)>) -> Result<(X509, Vec<u8>), &'static str> {
    let mut ca_cert = CertificateParameters::default(&cn);

    ca_cert.key_usage = vec![
            "digital_signature",
            "key_encipherment",
            "key_cert_sign",
            "critical",
    ];

    ca_cert.basic_constraints = Some(vec!["ca"]);

    if let Some(main_ca) = main_ca {
        let (main_ca_key, main_ca_cert) = main_ca;
        ca_cert.is_self_signed = false;
        ca_cert.ca_key = Some(&main_ca_key);
        ca_cert.ca_crt = Some(&main_ca_cert);
    }

    ca_cert.gen_cert()
}

pub fn gen_kubelet_cert(worker: &Instance, ca_key: &PKey<Private>, ca_cert: &X509) {
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
            "digital_signature",
            "key_encipherment",
            "critical",
        ],
        extended_key_usage: Some(vec!["server_auth"]),
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
    };

    let result = cert.gen_cert();

        let (certificate, key) = match result {
        Ok(result) => result,
        Err(error) => {
            eprintln!("{}", error);
            return
        }
    };

    let pem = certificate.to_pem().unwrap();

    let crt_filename = format!("certs/{}.crt", cert_filename);
    let key_filename = format!("certs/{}.key", cert_filename);

    fs::write(crt_filename, pem).expect("Unable to write file!");
    fs::write(key_filename, key).expect("Unable to write file!");
}

pub fn gen_etcd_cert(worker: &Instance, ca_key: &PKey<Private>, ca_cert: &X509) {
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
            "digital_signature",
            "key_encipherment",
            "critical",
        ],
        extended_key_usage: Some(vec!["server_auth"]),
        basic_constraints: None,

        san: Some(worker.san.iter().map(|s| s as &str).collect()),
        is_self_signed: false,
        ca_key: Some(&ca_key),
        ca_crt: Some(&ca_cert),
    };

    let result = cert.gen_cert();

    let (certificate, key) = match result {
        Ok(result) => result,
        Err(error) => {
            eprintln!("{}", error);
            return
        }
    };

    let pem = certificate.to_pem().unwrap();

    let crt_filename = format!("certs/etcd/{}.crt", cert_filename);
    let key_filename = format!("certs/etcd/{}.key", cert_filename);

    fs::write(crt_filename, pem).expect("Unable to write file!");
    fs::write(key_filename, key).expect("Unable to write file!");
}

pub fn kube_certs(ca_key: &PKey<Private>, ca_cert: &X509, config: &Config) {
    println!("Creating cert for Kubernetes API server");

    let mut api_client = CertificateParameters::default("kubernetes");

    api_client.key_usage = vec![
            "digital_signature",
            "key_encipherment",
            "critical",
    ];
    api_client.extended_key_usage = Some(vec![
        "server_auth",
    ]);

    api_client.san = Some(config.master_san.iter().map(|s| s as &str).collect());

    api_client.is_self_signed = false;
    api_client.ca_key = Some(&ca_key);
    api_client.ca_crt = Some(&ca_cert);

    match api_client.gen_cert() {
        Ok(bundle) => write_bundle_to_file(&bundle, "apiserver"),
        Err(error) => {
            eprintln!("{}", error);
            return
        }
    };


    println!("Creating cert for Kubernetes API server kubelet client");

    let mut api_client = CertificateParameters::default("kube-apiserver-kubelet-client");

    api_client.subject.organization = Some("system:masters");
    api_client.key_usage = vec![
            "digital_signature",
            "key_encipherment",
            "critical",
    ];
    api_client.extended_key_usage = Some(vec![
        "client_auth",
    ]);

    api_client.san = Some(config.master_san.iter().map(|s| s as &str).collect());

    api_client.is_self_signed = false;
    api_client.ca_key = Some(&ca_key);
    api_client.ca_crt = Some(&ca_cert);

    // let bundle = api_client.gen_cert();

    match api_client.gen_cert() {
        Ok(bundle) => write_bundle_to_file(&bundle, "apiserver-kubelet-client"),
        Err(error) => {
            eprintln!("{}", error);
            return
        }
    };

    println!("Creating cert: front-proxy-client");

    let mut api_client = CertificateParameters::default("front-proxy-client");

    api_client.key_usage = vec![
            "digital_signature",
            "key_encipherment",
            "critical",
    ];
    api_client.extended_key_usage = Some(vec![
        "client_auth",
    ]);

        api_client.is_self_signed = false;
        api_client.ca_key = Some(&ca_key);
        api_client.ca_crt = Some(&ca_cert);

    match api_client.gen_cert() {
        Ok(bundle) => write_bundle_to_file(&bundle, "front-proxy-client"),
        Err(error) => {
            eprintln!("{}", error);
            return
        }
    };
}


    //     CommonName                         Organization
    // let v: Vec<(&str, &str)> = vec![
    // ("system:kube-controller-manager", "system:kube-controller-manager"),
    // ("system:kube-proxy" ,"system:node-proxier"),
    // ("system:kube-scheduler" ,"system:kube-scheduler"),
    // ("service-accounts" ,"Kubernetes,")];
