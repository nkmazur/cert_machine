use std::fs;
use std::path::Path;
use openssl::x509::X509;
use openssl::pkey::Private;
use openssl::pkey::PKey;
use openssl::rsa::Rsa;
use config_parser::{Config, Instance};
use cert_machine::{CertificateParameters, Subject, Bundle};

fn opt_str(opt_string: &Option<String>) -> Option<&str> {
    match opt_string {
        Some(s) => Some(s.as_ref()),
        None => None,
    }
}

pub fn write_bundle_to_file(bundle: &Bundle, out_dir: &str, filename: &str) {
    let crt_filename = format!("{}/{}.crt", &out_dir, &filename);
    let key_filename = format!("{}/{}.key", &out_dir, &filename);

    match Path::new(&crt_filename).exists() {
        false => fs::write(&crt_filename, bundle.to_pem()).expect("Unable to write file!"),
        true => {
            eprintln!("File exists: {}!", crt_filename);
            return
        },
    }

    match Path::new(&key_filename).exists() {
        false => fs::write(&key_filename, &bundle.key).expect("Unable to write file!"),
        true => {
            eprintln!("File exists: {}!", key_filename);
            return
        },
    }
}

pub fn gen_main_ca_cert(config: &Config)  -> Result<Box<Bundle>, &'static str> {
    let ca_cert = CertificateParameters {
        key_length: config.ca.key_size,
        serial_number: 1,
        validity_days: config.ca.validity_days,
        subject: Subject {
            common_name: &config.cluster_name,
            country: opt_str(&config.ca.country),
            organization: opt_str(&config.ca.organization),
            organization_unit: opt_str(&config.ca.organization_unit),
            state_or_province_name: opt_str(&config.ca.state_or_province_name),
            locality: opt_str(&config.ca.locality),
        },
        key_usage: vec![
            "digital_signature",
            "key_encipherment",
            "key_cert_sign",
            "critical",
        ],
        extended_key_usage: None,
        basic_constraints: Some(vec!["ca"]),
        san: None,
        is_self_signed: true,
        ca_key: None,
        ca_crt: None,
    };

    println!("Creating CA with name: {}", config.cluster_name);
    ca_cert.gen_cert()
}

pub fn gen_ca_cert(cn: &str, main_ca: Option<&Box<Bundle>>) -> Result<Box<Bundle>, &'static str> {
    let (ca_key, ca_crt) = match main_ca {
        Some(bundle) => {
            let key = bundle.private_key();
            (Some(key), Some(bundle.cert.clone()))
        },
        None => (None, None)
    };

    let mut ca_cert = CertificateParameters::default(&cn);

    ca_cert.key_usage = vec![
            "digital_signature",
            "key_encipherment",
            "key_cert_sign",
            "critical",
    ];

    ca_cert.basic_constraints = Some(vec!["ca"]);

    if let Some(_) = main_ca {
        ca_cert.is_self_signed = false;
    }

    ca_cert.ca_key = ca_key.as_ref();
    ca_cert.ca_crt = ca_crt.as_ref();

    let ca_certificate = ca_cert.gen_cert();
    ca_certificate
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

        san: Some(worker.san.iter().map(|s| s as &str).collect()),
        is_self_signed: false,
        ca_key: Some(&ca_key),
        ca_crt: Some(&ca_cert),
    };

    match cert.gen_cert() {
        Ok(ref bundle) => write_bundle_to_file(&bundle, "certs",  &cert_filename),
        Err(err) => {
            println!("{}", err);
            return
        },
    }
}

pub fn gen_etcd_cert(worker: &Instance, ca_key: &PKey<Private>, ca_cert: &X509) {
    println!("Creating cert for Kubernetes ETCD client");

    let mut api_client = CertificateParameters::default("kube-apiserver-etcd-client");

    api_client.subject.organization = Some("system:masters");
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
        Ok(bundle) => write_bundle_to_file(&bundle, "certs", "apiserver-etcd-client"),
        Err(error) => {
            eprintln!("{}", error);
            return
        }
    };


    //-------------------------------------------------------
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
        extended_key_usage: Some(vec!["server_auth", "client_auth"]),
        basic_constraints: None,

        san: Some(worker.san.iter().map(|s| s as &str).collect()),
        is_self_signed: false,
        ca_key: Some(&ca_key),
        ca_crt: Some(&ca_cert),
    };

    match cert.gen_cert() {
        Ok(ref bundle) => write_bundle_to_file(&bundle, "certs/etcd",  &cert_filename),
        Err(err) => {
            println!("{}", err);
            return
        },
    }
}

pub fn kube_certs(ca_key: &PKey<Private>, ca_cert: &X509, config: &Config, out_dir: &str, front_ca: &Bundle) {
    println!("Creating cert for Kubernetes API server");

    let mut san: Vec<&str> = vec![
        "kubernetes",
        "kubernetes.default",
        "kubernetes.default.svc",
        "kubernetes.default.svc.cluster.local",
        "10.96.0.1",
    ];

    let san_from_confg: Vec<&str> = config.master_san.iter().map(|s| s as &str).collect();
    san.extend(san_from_confg);

    let mut api_client = CertificateParameters::default("kubernetes");

    api_client.key_usage = vec![
            "digital_signature",
            "key_encipherment",
            "critical",
    ];
    api_client.extended_key_usage = Some(vec![
        "server_auth",
    ]);

    api_client.san = Some(san.iter().map(|s| s as &str).collect());

    api_client.is_self_signed = false;
    api_client.ca_key = Some(&ca_key);
    api_client.ca_crt = Some(&ca_cert);

    match api_client.gen_cert() {
        Ok(bundle) => write_bundle_to_file(&bundle, &out_dir, "apiserver"),
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

    api_client.is_self_signed = false;
    api_client.ca_key = Some(&ca_key);
    api_client.ca_crt = Some(&ca_cert);

    match api_client.gen_cert() {
        Ok(bundle) => write_bundle_to_file(&bundle, &out_dir, "apiserver-kubelet-client"),
        Err(error) => {
            eprintln!("{}", error);
            return
        }
    };

    println!("Creating cert for Kubernetes admin");

    let mut api_client = CertificateParameters::default("admin");

    api_client.subject.organization = Some("system:masters");
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
        Ok(bundle) => write_bundle_to_file(&bundle, &out_dir, "admin"),
        Err(error) => {
            eprintln!("{}", error);
            return
        }
    };

    println!("Creating cert for Kubernetes controller-manager");

    let mut api_client = CertificateParameters::default("system:kube-controller-manager");

    api_client.subject.organization = Some("system:masters");
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
        Ok(bundle) => write_bundle_to_file(&bundle, &out_dir, "kube-controller-manager"),
        Err(error) => {
            eprintln!("{}", error);
            return
        }
    };

    println!("Creating cert for Kubernetes scheduler");

    let mut api_client = CertificateParameters::default("system:kube-scheduler");

    api_client.subject.organization = Some("system:masters");
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
        Ok(bundle) => write_bundle_to_file(&bundle, &out_dir, "kube-scheduler"),
        Err(error) => {
            eprintln!("{}", error);
            return
        }
    };

    println!("Creating cert for Kubernetes proxy");

    let mut api_client = CertificateParameters::default("system:kube-proxy");

    api_client.subject.organization = Some("system:node-proxier");
    api_client.key_usage = vec![
            "digital_signature",
            "key_encipherment",
            "critical",
    ];
    api_client.extended_key_usage = Some(vec![
        "client_auth",
        "server_auth",
    ]);

    api_client.is_self_signed = false;
    api_client.ca_key = Some(&ca_key);
    api_client.ca_crt = Some(&ca_cert);

    match api_client.gen_cert() {
        Ok(bundle) => write_bundle_to_file(&bundle, &out_dir, "kube-proxy"),
        Err(error) => {
            eprintln!("{}", error);
            return
        }
    };

    println!("Creating cert: front-proxy-client");

    let front_key = front_ca.private_key();

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
        api_client.ca_key = Some(&front_key);
        api_client.ca_crt = Some(&front_ca.cert);

    match api_client.gen_cert() {
        Ok(bundle) => write_bundle_to_file(&bundle, &out_dir, "front-proxy-client"),
        Err(error) => {
            eprintln!("{}", error);
            return
        }
    };

    let rsa = Rsa::generate(2048).unwrap();
    let key = rsa.private_key_to_pem().unwrap();
    let pkey = PKey::from_rsa(rsa).unwrap().public_key_to_pem().unwrap();

    fs::write("certs/sa.pub", pkey).expect("Unable to write file!");
    fs::write("certs/sa.key", key).expect("Unable to write file!");
}
