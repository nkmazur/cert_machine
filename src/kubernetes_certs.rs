use CA;
use std::fs;
use std::path::Path;
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
        ca: None,
    };

    ca_cert.gen_cert()
}

pub fn gen_ca_cert(cn: &str, main_ca: Option<&Box<Bundle>>, config: &Config) -> Result<Box<Bundle>, &'static str> {
    let mut ca_cert = CertificateParameters::default(&cn);

    ca_cert.ca = main_ca;
    ca_cert.key_usage = vec![
            "digital_signature",
            "key_encipherment",
            "key_cert_sign",
            "critical",
    ];

    ca_cert.basic_constraints = Some(vec!["ca"]);

    if let Some(size) = config.key_size {
        ca_cert.key_length = size;
    }

    if let Some(validity) = config.validity_days {
        ca_cert.validity_days = validity;
    }

    ca_cert.ca = main_ca;

    let ca_certificate = ca_cert.gen_cert();
    ca_certificate
}

pub fn gen_kubelet_cert(worker: &Instance, ca: Option<&Box<Bundle>>, config: &Config) {
    println!("Creating cert for node: {}", worker.hostname);

    let cert_filename = if let Some(ref filename) = worker.filename {
        filename.to_owned()
    } else {
        worker.hostname.clone()
    };

    let cn = &format!("system:node:{}", &worker.hostname);

    let mut cert = CertificateParameters::client(&cn);
    cert.subject.organization = Some("system:nodes");
    cert.san = Some(worker.san.iter().map(|s| s as &str).collect());
    cert.ca = ca;

    if let Some(size) = config.key_size {
        cert.key_length = size;
    }

    if let Some(validity) = config.validity_days {
        cert.validity_days = validity;
    }

    match cert.gen_cert() {
        Ok(ref bundle) => write_bundle_to_file(&bundle, "certs",  &cert_filename),
        Err(err) => {
            println!("{}", err);
            return
        },
    }
}

pub fn gen_etcd_cert(worker: &Instance, ca: Option<&Box<Bundle>>, config: &Config) {
    println!("Creating cert for etcd node: {}", worker.hostname);

    let cert_filename = if let Some(ref filename) = worker.filename {
        filename.to_owned()
    } else {
        worker.hostname.clone()
    };

    let mut cert = CertificateParameters::client(&&worker.hostname);
    cert.extended_key_usage = Some(vec!["server_auth", "client_auth"]);
    cert.san = Some(worker.san.iter().map(|s| s as &str).collect());
    cert.ca = ca;

    if let Some(size) = config.key_size {
        cert.key_length = size;
    }

    if let Some(validity) = config.validity_days {
        cert.validity_days = validity;
    }

    match cert.gen_cert() {
        Ok(ref bundle) => write_bundle_to_file(&bundle, "certs/etcd",  &cert_filename),
        Err(err) => {
            println!("{}", err);
            return
        },
    }
}

pub fn kube_certs(ca: &CA, config: &Config, out_dir: &str) {
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

    let mut api_server = CertificateParameters::server("kubernetes");
    api_server.san = Some(san.iter().map(|s| s as &str).collect());
    api_server.ca = Some(&ca.main_ca);

    if let Some(size) = config.key_size {
        api_server.key_length = size;
    }

    if let Some(validity) = config.validity_days {
        api_server.validity_days = validity;
    }

    match api_server.gen_cert() {
        Ok(bundle) => write_bundle_to_file(&bundle, &out_dir, "apiserver"),
        Err(error) => {
            eprintln!("{}", error);
            return
        }
    };


    println!("Creating cert for Kubernetes API server kubelet client");

    let mut api_client = CertificateParameters::client("kube-apiserver-kubelet-client");

    api_client.subject.organization = Some("system:masters");
    api_client.ca = Some(&ca.main_ca);

    if let Some(size) = config.key_size {
        api_client.key_length = size;
    }

    if let Some(validity) = config.validity_days {
        api_client.validity_days = validity;
    }

    match api_client.gen_cert() {
        Ok(bundle) => write_bundle_to_file(&bundle, &out_dir, "apiserver-kubelet-client"),
        Err(error) => {
            eprintln!("{}", error);
            return
        }
    };

    println!("Creating cert for Kubernetes ETCD client");

    let mut api_client = CertificateParameters::client("kube-apiserver-etcd-client");
    api_client.subject.organization = Some("system:masters");
    api_client.ca = Some(&ca.etcd_ca);

    if let Some(size) = config.key_size {
        api_client.key_length = size;
    }

    if let Some(validity) = config.validity_days {
        api_client.validity_days = validity;
    }

    match api_client.gen_cert() {
        Ok(bundle) => write_bundle_to_file(&bundle, "certs", "apiserver-etcd-client"),
        Err(error) => {
            eprintln!("{}", error);
            return
        }
    };

    println!("Creating cert for Kubernetes admin");

    let mut admin = CertificateParameters::client("admin");

    admin.subject.organization = Some("system:masters");
    admin.ca = Some(&ca.main_ca);

    if let Some(size) = config.key_size {
        admin.key_length = size;
    }

    if let Some(validity) = config.validity_days {
        admin.validity_days = validity;
    }

    match admin.gen_cert() {
        Ok(bundle) => write_bundle_to_file(&bundle, &out_dir, "admin"),
        Err(error) => {
            eprintln!("{}", error);
            return
        }
    };

    println!("Creating cert for Kubernetes controller-manager");

    let mut kube_cm = CertificateParameters::client("system:kube-controller-manager");

    kube_cm.subject.organization = Some("system:masters");

    kube_cm.ca = Some(&ca.main_ca);

    if let Some(size) = config.key_size {
        kube_cm.key_length = size;
    }

    if let Some(validity) = config.validity_days {
        kube_cm.validity_days = validity;
    }

    match kube_cm.gen_cert() {
        Ok(bundle) => write_bundle_to_file(&bundle, &out_dir, "kube-controller-manager"),
        Err(error) => {
            eprintln!("{}", error);
            return
        }
    };

    println!("Creating cert for Kubernetes scheduler");

    let mut scheduler = CertificateParameters::client("system:kube-scheduler");

    scheduler.subject.organization = Some("system:masters");
    scheduler.ca = Some(&ca.main_ca);

    if let Some(size) = config.key_size {
        scheduler.key_length = size;
    }

    if let Some(validity) = config.validity_days {
        scheduler.validity_days = validity;
    }

    match scheduler.gen_cert() {
        Ok(bundle) => write_bundle_to_file(&bundle, &out_dir, "kube-scheduler"),
        Err(error) => {
            eprintln!("{}", error);
            return
        }
    };

    println!("Creating cert for Kubernetes proxy");

    let mut proxy = CertificateParameters::client("system:kube-proxy");
    proxy.subject.organization = Some("system:node-proxier");
    proxy.ca = Some(&ca.main_ca);

    if let Some(size) = config.key_size {
        proxy.key_length = size;
    }

    if let Some(validity) = config.validity_days {
        proxy.validity_days = validity;
    }

    match proxy.gen_cert() {
        Ok(bundle) => write_bundle_to_file(&bundle, &out_dir, "kube-proxy"),
        Err(error) => {
            eprintln!("{}", error);
            return
        }
    };

    println!("Creating cert: front-proxy-client");

    let mut fpc = CertificateParameters::client("front-proxy-client");
    fpc.ca = Some(&ca.front_ca);

    if let Some(size) = config.key_size {
        fpc.key_length = size;
    }

    if let Some(validity) = config.validity_days {
        fpc.validity_days = validity;
    }

    match fpc.gen_cert() {
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
