use cert_machine::{Bundle, CertificateParameters, Subject};
use config_parser::{Config, Instance};
use create_symlink;
use openssl::bn::BigNum;
use openssl::pkey::PKey;
use openssl::rsa::Rsa;
use std::fs;
use std::fs::File;
use std::fs::OpenOptions;
use std::io;
use std::io::prelude::*;
use std::os::unix::fs::symlink;
use std::path::Path;
use std::process::exit;
use CA;

pub enum CertType<'a> {
    Admin,
    ApiServer,
    ApiServerClient,
    ApiServerEtcdClient,
    ControllerManager,
    FrontProxy,
    Scheduler,
    Proxy,
    EtcdServer(&'a Instance),
    Kubelet(&'a Instance),
    KubeletServer(&'a Instance),
}

fn opt_str(opt_string: &Option<String>) -> Option<&str> {
    match opt_string {
        Some(s) => Some(s.as_ref()),
        None => None,
    }
}

pub fn write_bundle_to_file(
    bundle: &Bundle,
    out_dir: &str,
    filename: &str,
    overwrite: bool,
) -> Result<(), io::Error> {
    let sn = bundle.cert.serial_number().to_bn().unwrap();
    let (crt_filename, key_filename) = match filename {
        "ca" => {
            let crt_filename = format!("{}/certs/{}.crt", &out_dir, &filename);
            let key_filename = format!("{}/keys/{}.key", &out_dir, &filename);
            (crt_filename, key_filename)
        }
        _ => {
            let crt_filename = format!("{}/certs/{}-{}.crt", &out_dir, &filename, sn);
            let key_filename = format!("{}/keys/{}-{}.key", &out_dir, &filename, sn);
            (crt_filename, key_filename)
        }
    };
    println!("Write to:\n{}\n{}", &crt_filename, &key_filename);

    match Path::new(&crt_filename).exists() {
        false => fs::write(&crt_filename, bundle.to_pem()).expect("Unable to write cert!"),
        true => {
            if overwrite {
                println!("OVERWRITING: {}", &crt_filename);
                fs::write(&crt_filename, bundle.to_pem()).expect("Unable to write cert!");
            } else {
                eprintln!("File exists: {}!", crt_filename);
            }
        }
    }
    match Path::new(&key_filename).exists() {
        false => fs::write(&key_filename, &bundle.key).expect("Unable to write key!"),
        true => {
            if overwrite {
                println!("OVERWRITING: {}", &crt_filename);
                fs::write(&key_filename, &bundle.key).expect("Unable to write key!");
            } else {
                eprintln!("File exists: {}!", key_filename);
                return Ok(());
            }
        }
    }
    // let mut sn = bundle.cert.serial_number().to_bn().expect("Unable to get serial number from cert!");
    let index_filename = format!("{}/index", &out_dir);
    // sn.add_word(1).unwrap();
    println!("Index filename: {}\nWroted sn: {}", &index_filename, &sn);
    match write_sn(&index_filename, sn) {
        Ok(_) => (),
        Err(err) => panic!(
            "Error when writing index file: {}, file: {}",
            err, &index_filename
        ),
    }
    Ok(())
}

fn get_sn(filename: &str) -> Result<u32, io::Error> {
    match Path::new(&filename).exists() {
        false => {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&filename)
                .unwrap();
            let sn: u32 = 0;
            file.write_all(sn.to_string().as_bytes()).unwrap();
            Ok(sn)
        }
        true => {
            let mut file = File::open(&filename)?;
            let mut contents = String::new();
            file.read_to_string(&mut contents)?;
            let sn: u32 = match contents.trim().parse() {
                Ok(num) => num,
                Err(err) => {
                    panic!("Unable to read index from index file: {}", err);
                }
            };
            println!("Got sn: {}", sn);
            Ok(sn)
        }
    }
}

fn write_sn(filename: &str, sn: BigNum) -> Result<(), io::Error> {
    let mut file = OpenOptions::new().write(true).open(&filename)?;
    file.write_all(sn.to_string().as_bytes()).unwrap();
    Ok(())
}

pub fn create_directory_struct(config: &Config, root_dir: &str) -> io::Result<()> {
    let root_ca_certs = format!("{}/CA/root/certs", root_dir);
    let root_ca_keys = format!("{}/CA/root/keys", root_dir);
    let etcd_ca_certs = format!("{}/CA/etcd/certs", root_dir);
    let etcd_ca_keys = format!("{}/CA/etcd/keys", root_dir);
    let front_ca_certs = format!("{}/CA/front-proxy/certs", root_dir);
    let front_ca_keys = format!("{}/CA/front-proxy/keys", root_dir);
    let master_dir = format!("{}/master", root_dir);
    fs::create_dir_all(root_ca_certs)?;
    fs::create_dir_all(root_ca_keys)?;
    fs::create_dir_all(etcd_ca_certs)?;
    fs::create_dir_all(etcd_ca_keys)?;
    fs::create_dir_all(front_ca_certs)?;
    fs::create_dir_all(front_ca_keys)?;
    fs::create_dir_all(master_dir)?;
    for worker in config.worker.iter() {
        let worker_dir = if let Some(ref filename) = worker.filename {
            filename.to_owned()
        } else {
            worker.hostname.clone()
        };
        let dir = format!("{}/{}", root_dir, worker_dir);
        fs::create_dir_all(dir)?;
    }
    for etcd_server in config.etcd_server.iter() {
        let etcd_dir = if let Some(ref filename) = etcd_server.filename {
            filename.to_owned()
        } else {
            etcd_server.hostname.clone()
        };
        let dir = format!("{}/{}", root_dir, etcd_dir);
        fs::create_dir_all(dir)?;
    }
    Ok(())
}

pub fn gen_main_ca_cert(config: &Config) -> Result<Box<Bundle>, &'static str> {
    let ca_cert = CertificateParameters {
        key_length: config.ca.key_size,
        serial_number: 0,
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

pub fn gen_ca_cert(
    cn: &str,
    main_ca: Option<&Box<Bundle>>,
    config: &Config,
) -> Result<Box<Bundle>, &'static str> {
    let mut ca_cert = CertificateParameters::ca(&cn, config.ca.key_size, config.ca.validity_days);
    ca_cert.ca = main_ca;
    ca_cert.gen_cert()
}

pub fn gen_kubelet_cert(
    worker: &Instance,
    ca: Option<&Box<Bundle>>,
    config: &Config,
) -> Result<Box<Bundle>, &'static str> {
    println!("Creating cert for node: {}", worker.hostname);

    let cn = &format!("system:node:{}", &worker.hostname);

    let mut client_cert = CertificateParameters::client(&cn, config.key_size, config.validity_days);
    let index_filename = format!("{}/CA/root/index", &config.out_dir);
    client_cert.serial_number = match get_sn(&index_filename) {
        Ok(sn) => sn + 1,
        Err(err) => panic!(
            "Error when gettitng index: {}, file: {}",
            err, &index_filename
        ),
    };
    client_cert.subject.organization = Some("system:nodes");
    client_cert.ca = ca;

    client_cert.gen_cert()
}

pub fn gen_kubelet_server_cert(
    worker: &Instance,
    ca: Option<&Box<Bundle>>,
    config: &Config,
) -> Result<Box<Bundle>, &'static str> {
    println!("Creating server cert for node: {}", worker.hostname);

    let mut server_cert =
        CertificateParameters::server(&worker.hostname, config.key_size, config.validity_days);
    let index_filename = format!("{}/CA/root/index", &config.out_dir);
    server_cert.serial_number = match get_sn(&index_filename) {
        Ok(sn) => sn + 1,
        Err(err) => panic!(
            "Error when gettitng index: {}, file: {}",
            err, &index_filename
        ),
    };
    server_cert.san = Some(worker.san.iter().map(|s| s as &str).collect());
    server_cert.ca = ca;

    server_cert.gen_cert()
}

pub fn gen_etcd_cert(
    worker: &Instance,
    ca: Option<&Box<Bundle>>,
    config: &Config,
) -> Result<Box<Bundle>, &'static str> {
    println!("Creating cert for etcd node: {}", worker.hostname);
    let index_filename = format!("{}/CA/etcd/index", &config.out_dir);
    let mut cert = CertificateParameters::client_and_server(
        &worker.hostname,
        config.key_size,
        config.validity_days,
    );
    cert.serial_number = match get_sn(&index_filename) {
        Ok(sn) => sn + 1,
        Err(err) => {
            eprintln!(
                "Error when gettitng index: {}, file: {}",
                err, &index_filename
            );
            exit(1);
        }
    };
    cert.san = Some(worker.san.iter().map(|s| s as &str).collect());
    cert.ca = ca;
    cert.gen_cert()
}

pub fn kube_certs(ca: &CA, config: &Config, out_dir: &str) {
    let main_ca_dir = format!("{}/CA/root", &out_dir);
    let etcd_ca_dir = format!("{}/CA/etcd", &out_dir);
    let front_ca_dir = format!("{}/CA/front-proxy", &out_dir);
    match gen_cert(&ca, &config, &CertType::Admin) {
        Ok(bundle) => {
            let filename = format!("admin-{}", bundle.cert.serial_number().to_bn().unwrap());
            let symlink_path = format!("{}/master/admin", &out_dir);
            write_bundle_to_file(&bundle, &main_ca_dir, "admin", config.overwrite).unwrap();
            create_symlink("../CA/root", &filename, &symlink_path);
        }
        Err(err) => panic!("Error: {}", err),
    }
    match gen_cert(&ca, &config, &CertType::ApiServer) {
        Ok(bundle) => {
            let filename = format!("apiserver-{}", bundle.cert.serial_number().to_bn().unwrap());
            let symlink_path = format!("{}/master/apiserver", &out_dir);
            write_bundle_to_file(&bundle, &main_ca_dir, "apiserver", config.overwrite).unwrap();
            create_symlink("../CA/root", &filename, &symlink_path);
        }
        Err(err) => panic!("Error: {}", err),
    }
    match gen_cert(&ca, &config, &CertType::ApiServerClient) {
        Ok(bundle) => {
            let filename = format!(
                "apiserver-kubelet-client-{}",
                bundle.cert.serial_number().to_bn().unwrap()
            );
            let symlink_path = format!("{}/master/apiserver-kubelet-client", &out_dir);
            write_bundle_to_file(
                &bundle,
                &main_ca_dir,
                "apiserver-kubelet-client",
                config.overwrite,
            ).unwrap();
            create_symlink("../CA/root", &filename, &symlink_path);
        }
        Err(err) => panic!("Error: {}", err),
    }
    match gen_cert(&ca, &config, &CertType::ApiServerEtcdClient) {
        Ok(bundle) => {
            let filename = format!(
                "apiserver-etcd-client-{}",
                bundle.cert.serial_number().to_bn().unwrap()
            );
            let symlink_path = format!("{}/master/apiserver-etcd-client", &out_dir);
            write_bundle_to_file(
                &bundle,
                &etcd_ca_dir,
                "apiserver-etcd-client",
                config.overwrite,
            ).unwrap();
            create_symlink("../CA/etcd", &filename, &symlink_path);
        }
        Err(err) => panic!("Error: {}", err),
    }
    match gen_cert(&ca, &config, &CertType::ControllerManager) {
        Ok(bundle) => {
            let filename = format!(
                "kube-controller-manager-{}",
                bundle.cert.serial_number().to_bn().unwrap()
            );
            let symlink_path = format!("{}/master/kube-controller-manager", &out_dir);
            write_bundle_to_file(
                &bundle,
                &main_ca_dir,
                "kube-controller-manager",
                config.overwrite,
            ).unwrap();
            create_symlink("../CA/root", &filename, &symlink_path);
        }
        Err(err) => panic!("Error: {}", err),
    }
    match gen_cert(&ca, &config, &CertType::Scheduler) {
        Ok(bundle) => {
            let filename = format!(
                "kube-scheduler-{}",
                bundle.cert.serial_number().to_bn().unwrap()
            );
            let symlink_path = format!("{}/master/kube-scheduler", &out_dir);
            write_bundle_to_file(&bundle, &main_ca_dir, "kube-scheduler", config.overwrite)
                .unwrap();
            create_symlink("../CA/root", &filename, &symlink_path);
        }
        Err(err) => panic!("Error: {}", err),
    }
    match gen_cert(&ca, &config, &CertType::FrontProxy) {
        Ok(bundle) => {
            let filename = format!(
                "front-proxy-client-{}",
                bundle.cert.serial_number().to_bn().unwrap()
            );
            let symlink_path = format!("{}/master/front-proxy-client", &out_dir);
            write_bundle_to_file(
                &bundle,
                &front_ca_dir,
                "front-proxy-client",
                config.overwrite,
            ).unwrap();
            create_symlink("../CA/front-proxy", &filename, &symlink_path);
        }
        Err(err) => panic!("Error: {}", err),
    }
    match gen_cert(&ca, &config, &CertType::Proxy) {
        Ok(bundle) => {
            let filename = format!(
                "kube-proxy-{}",
                bundle.cert.serial_number().to_bn().unwrap()
            );
            let symlink_path = format!("{}/master/kube-proxy", &out_dir);
            write_bundle_to_file(&bundle, &main_ca_dir, "kube-proxy", config.overwrite).unwrap();
            create_symlink("../CA/root", &filename, &symlink_path);
            for worker in config.worker.iter() {
                let mut cert_filename = match worker.filename {
                    Some(ref filename) => filename.to_owned(),
                    None => worker.hostname.clone(),
                };
                let node_symlink_path = format!("{}/{}/kube-proxy", &out_dir, &cert_filename);
                create_symlink("../CA/root", &filename, &node_symlink_path);
            }
        }
        Err(err) => panic!("Error: {}", err),
    }

    let rsa = Rsa::generate(2048).unwrap();
    let key = rsa.private_key_to_pem().unwrap();
    let pkey = PKey::from_rsa(rsa).unwrap().public_key_to_pem().unwrap();

    let sa_pub_filename = format!("{}/sa.pub", &out_dir);
    let sa_pub_symlink = format!("{}/master/sa.pub", &out_dir);
    let sa_key_filename = format!("{}/sa.key", &out_dir);
    let sa_key_symlink = format!("{}/master/sa.key", &out_dir);

    fs::write(&sa_pub_filename, pkey).expect("Unable to write file!");
    fs::write(&sa_key_filename, key).expect("Unable to write file!");
    symlink(&sa_pub_filename, &sa_pub_symlink).unwrap();
    symlink(&sa_key_filename, &sa_key_symlink).unwrap();
}

pub fn admin_cert(
    ca: &Box<Bundle>,
    config: &Config,
    serial_number: u32,
) -> Result<Box<Bundle>, &'static str> {
    println!("Creating cert for Kubernetes admin");
    let mut admin = CertificateParameters::client("admin", config.key_size, config.validity_days);
    admin.subject.organization = Some("system:masters");
    admin.ca = Some(&ca);
    admin.serial_number = serial_number;
    admin.gen_cert()
}

pub fn apiserver_cert(
    ca: &Box<Bundle>,
    config: &Config,
    serial_number: u32,
) -> Result<Box<Bundle>, &'static str> {
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

    let mut api_server =
        CertificateParameters::server("kubernetes", config.key_size, config.validity_days);
    api_server.san = Some(san.iter().map(|s| s as &str).collect());
    api_server.ca = Some(&ca);
    api_server.serial_number = serial_number;
    api_server.gen_cert()
}

pub fn apiserver_client_cert(
    ca: &Box<Bundle>,
    config: &Config,
    serial_number: u32,
) -> Result<Box<Bundle>, &'static str> {
    println!("Creating cert for Kubernetes API server kubelet client");
    let mut api_client = CertificateParameters::client(
        "kube-apiserver-kubelet-client",
        config.key_size,
        config.validity_days,
    );
    api_client.subject.organization = Some("system:masters");
    api_client.ca = Some(&ca);
    api_client.serial_number = serial_number;
    api_client.gen_cert()
}

pub fn apiserver_etcd_client_cert(
    ca: &Box<Bundle>,
    config: &Config,
    serial_number: u32,
) -> Result<Box<Bundle>, &'static str> {
    println!("Creating cert for Kubernetes ETCD client");
    let mut api_client = CertificateParameters::client(
        "kube-apiserver-etcd-client",
        config.key_size,
        config.validity_days,
    );
    api_client.subject.organization = Some("system:masters");
    api_client.ca = Some(&ca);
    api_client.serial_number = serial_number;
    api_client.gen_cert()
}

pub fn controller_manager_cert(
    ca: &Box<Bundle>,
    config: &Config,
    serial_number: u32,
) -> Result<Box<Bundle>, &'static str> {
    println!("Creating cert for Kubernetes controller-manager");
    let mut kube_cm = CertificateParameters::client(
        "system:kube-controller-manager",
        config.key_size,
        config.validity_days,
    );
    kube_cm.subject.organization = Some("system:masters");
    kube_cm.serial_number = serial_number;
    kube_cm.ca = Some(&ca);
    kube_cm.gen_cert()
}

pub fn scheduler_cert(
    ca: &Box<Bundle>,
    config: &Config,
    serial_number: u32,
) -> Result<Box<Bundle>, &'static str> {
    println!("Creating cert for Kubernetes scheduler");
    let mut scheduler = CertificateParameters::client(
        "system:kube-scheduler",
        config.key_size,
        config.validity_days,
    );
    scheduler.subject.organization = Some("system:masters");
    scheduler.ca = Some(&ca);
    scheduler.serial_number = serial_number;
    scheduler.gen_cert()
}

pub fn proxy_cert(
    ca: &Box<Bundle>,
    config: &Config,
    serial_number: u32,
) -> Result<Box<Bundle>, &'static str> {
    println!("Creating cert for Kubernetes proxy");
    let mut proxy =
        CertificateParameters::client("system:kube-proxy", config.key_size, config.validity_days);
    proxy.subject.organization = Some("system:node-proxier");
    proxy.serial_number = serial_number;
    proxy.ca = Some(&ca);
    proxy.gen_cert()
}

pub fn front_proxy_cert(
    ca: &Box<Bundle>,
    config: &Config,
    serial_number: u32,
) -> Result<Box<Bundle>, &'static str> {
    println!("Creating cert: front-proxy-client");
    let mut fpc =
        CertificateParameters::client("front-proxy-client", config.key_size, config.validity_days);
    fpc.serial_number = serial_number;
    fpc.ca = Some(&ca);
    fpc.gen_cert()
}

pub fn gen_cert(
    ca: &CA,
    config: &Config,
    cert_type: &CertType,
) -> Result<Box<Bundle>, &'static str> {
    let root_index_filename = format!("{}/CA/root/index", &config.out_dir);
    // let etcd_index_filename  = format!("{}/CA/root/index", &config.out_dir);
    // let front_index_filename  = format!("{}/CA/root/index", &config.out_dir);
    let sn = match get_sn(&root_index_filename) {
        Ok(sn) => sn + 1,
        Err(err) => panic!(
            "Error when gettitng index: {}, file: {}",
            err, &root_index_filename
        ),
    };
    match cert_type {
        CertType::Admin => admin_cert(&ca.main_ca, &config, sn),
        CertType::ApiServer => apiserver_cert(&ca.main_ca, &config, sn),
        CertType::ApiServerClient => apiserver_client_cert(&ca.main_ca, &config, sn),
        CertType::ApiServerEtcdClient => {
            let index_filename = format!("{}/CA/etcd/index", &config.out_dir);
            let sn = match get_sn(&index_filename) {
                Ok(sn) => sn + 1,
                Err(err) => panic!(
                    "Error when gettitng index: {}, file: {}",
                    err, &index_filename
                ),
            };
            apiserver_etcd_client_cert(&ca.etcd_ca, &config, sn)
        }
        CertType::ControllerManager => controller_manager_cert(&ca.main_ca, &config, sn),
        CertType::FrontProxy => {
            let index_filename = format!("{}/CA/front-proxy/index", &config.out_dir);
            let sn = match get_sn(&index_filename) {
                Ok(sn) => sn + 1,
                Err(err) => panic!(
                    "Error when gettitng index: {}, file: {}",
                    err, &index_filename
                ),
            };
            front_proxy_cert(&ca.front_ca, &config, sn)
        }
        CertType::Scheduler => scheduler_cert(&ca.main_ca, &config, sn),
        CertType::Proxy => proxy_cert(&ca.main_ca, &config, sn),
        CertType::EtcdServer(etcd_instance) => gen_etcd_cert(&etcd_instance, Some(&ca.etcd_ca), &config),
        CertType::Kubelet(ref worker) => gen_kubelet_cert(&worker, Some(&ca.main_ca), &config),
        CertType::KubeletServer(ref worker) => gen_kubelet_server_cert(&worker, Some(&ca.main_ca), &config),
    }
}
