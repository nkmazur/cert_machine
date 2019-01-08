use cert_machine::{Bundle, CertificateParameters, Subject};
use config_parser::{Config, Instance, User};
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
    EtcdUser(&'a str),
    Kubelet(&'a Instance),
    KubeletServer(&'a Instance),
    User(&'a User),
}

pub fn opt_str(opt_string: &Option<String>) -> Option<&str> {
    match opt_string {
        Some(s) => Some(s.as_ref()),
        None => None,
    }
}

pub fn write_bundle_to_file(bundle: &Bundle, out_dir: &str, filename: &str, overwrite: bool) -> Result<(), io::Error> {
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
    let index_filename = format!("{}/index", &out_dir);
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
            // println!("Got sn: {}", sn);
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
    let users_dir = format!("{}/users", root_dir);
    let etcd_users_dir = format!("{}/etcd-users", root_dir);
    fs::create_dir_all(root_ca_certs)?;
    fs::create_dir_all(root_ca_keys)?;
    fs::create_dir_all(etcd_ca_certs)?;
    fs::create_dir_all(etcd_ca_keys)?;
    fs::create_dir_all(front_ca_certs)?;
    fs::create_dir_all(front_ca_keys)?;
    fs::create_dir_all(master_dir)?;
    fs::create_dir_all(users_dir)?;
    fs::create_dir_all(etcd_users_dir)?;
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

pub fn gen_ca_cert(cn: &str, main_ca: Option<&Box<Bundle>>, config: &Config) -> Result<Box<Bundle>, &'static str> {
    let mut ca_cert = CertificateParameters::ca(&cn, config.ca.key_size, config.ca.validity_days);
    ca_cert.ca = main_ca;
    ca_cert.gen_cert()
}

pub fn gen_kubelet_cert(worker: &Instance, ca: Option<&Box<Bundle>>, config: &Config,) -> Result<Box<Bundle>, &'static str> {
    println!("Creating cert for node: {}", worker.hostname);

    let mut cert_filename = match worker.filename {
        Some(ref filename) => filename.to_owned(),
        None => worker.hostname.clone(),
    };

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

    let bundle = client_cert.gen_cert()?;
    let node_cert_path = format!("{}/{}/node-kubeconfig", &config.out_dir, &cert_filename);
    let outdir = format!("{}/CA/root", &config.out_dir);

    cert_filename.push_str("-kubeconfig");

    match write_bundle_to_file(&bundle, &outdir, &cert_filename, config.overwrite) {
        Ok(_) => (),
        Err(err) => panic!("Error, when writing cert: {}", err),
    }
    let sn = &bundle.cert.serial_number().to_bn().unwrap();
    let cert_name = format!("{}-{}", &cert_filename, sn);
    create_symlink("../CA/root", &cert_name, &node_cert_path);
    Ok(bundle)
}

pub fn gen_kubelet_server_cert(worker: &Instance, ca: Option<&Box<Bundle>>, config: &Config) -> Result<Box<Bundle>, &'static str> {
    println!("Creating server cert for node: {}", worker.hostname);

    let cert_filename = match worker.filename {
        Some(ref filename) => filename.to_owned(),
        None => worker.hostname.clone(),
    };

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

    let bundle = server_cert.gen_cert()?;
    let outdir = format!("{}/CA/root", &config.out_dir);
    match write_bundle_to_file(&bundle, &outdir, &cert_filename, config.overwrite) {
        Ok(_) => (),
        Err(err) => panic!("Error, when writing cert: {}", err),
    }
    let sn = &bundle.cert.serial_number().to_bn().unwrap();
    let cert_name = format!("{}-{}", &cert_filename, sn);
    let node_cert_path = format!("{}/{}/node", &config.out_dir, &cert_filename);
    create_symlink("../CA/root", &cert_name, &node_cert_path);
    Ok(bundle)
}

pub fn gen_etcd_cert(worker: &Instance, ca: Option<&Box<Bundle>>, config: &Config) -> Result<Box<Bundle>, &'static str> {
    println!("Creating cert for etcd node: {}", worker.hostname);
    let cert_filename = match worker.filename {
        Some(ref filename) => filename.to_owned(),
        None => worker.hostname.clone(),
    };
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
    let bundle = cert.gen_cert()?;
    let outdir = format!("{}/CA/etcd", &config.out_dir);
    write_bundle_to_file(&bundle, &outdir, &cert_filename, config.overwrite).unwrap();
    let cn = &bundle.cert.serial_number().to_bn().unwrap();
    let cert_name = format!("{}-{}", &cert_filename, cn);
    let node_cert_path = format!("{}/{}/etcd", &config.out_dir, &cert_filename);
    create_symlink("../CA/etcd", &cert_name, &node_cert_path);
    Ok(bundle)
}

pub fn gen_etcd_user(username: &str, ca: Option<&Box<Bundle>>, config: &Config) -> Result<Box<Bundle>, &'static str> {
    let index_filename = format!("{}/CA/etcd/index", &config.out_dir);
    let mut cert = CertificateParameters::client(
        &username,
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
    cert.ca = ca;
    let bundle = cert.gen_cert()?;
    let outdir = format!("{}/CA/etcd", &config.out_dir);
    write_bundle_to_file(&bundle, &outdir, &username, config.overwrite).unwrap();
    let cn = &bundle.cert.serial_number().to_bn().unwrap();
    let cert_name = format!("{}-{}", &username, cn);
    let node_cert_path = format!("{}/etcd-users/{}", &config.out_dir, &username);
    create_symlink("../CA/etcd", &cert_name, &node_cert_path);
    Ok(bundle)
}

pub fn kube_certs(ca: &CA, config: &Config, out_dir: &str) {
    gen_cert(&ca, &config, &CertType::Admin).unwrap();
    gen_cert(&ca, &config, &CertType::ApiServer).unwrap();
    gen_cert(&ca, &config, &CertType::ApiServerClient).unwrap();
    gen_cert(&ca, &config, &CertType::ApiServerEtcdClient).unwrap();
    gen_cert(&ca, &config, &CertType::ControllerManager).unwrap();
    gen_cert(&ca, &config, &CertType::Scheduler).unwrap();
    gen_cert(&ca, &config, &CertType::FrontProxy).unwrap();
    gen_cert(&ca, &config, &CertType::Proxy).unwrap();

    let rsa = Rsa::generate(2048).unwrap();
    let key = rsa.private_key_to_pem().unwrap();
    let pkey = PKey::from_rsa(rsa).unwrap().public_key_to_pem().unwrap();

    let sa_pub_filename = format!("{}/sa.pub", &out_dir);
    let sa_pub_symlink = format!("{}/master/sa.pub", &out_dir);
    let sa_key_filename = format!("{}/sa.key", &out_dir);
    let sa_key_symlink = format!("{}/master/sa.key", &out_dir);

    fs::write(&sa_pub_filename, pkey).expect("Unable to write file!");
    fs::write(&sa_key_filename, key).expect("Unable to write file!");
    symlink("../sa.pub", &sa_pub_symlink).unwrap();
    symlink("../sa.key", &sa_key_symlink).unwrap();
}

pub fn admin_cert(ca: &Box<Bundle>, config: &Config, serial_number: u32) -> Result<Box<Bundle>, &'static str> {
    println!("Creating cert for Kubernetes admin");
    let mut admin = CertificateParameters::client("admin", config.key_size, config.validity_days);
    admin.subject.organization = Some("system:masters");
    admin.ca = Some(&ca);
    admin.serial_number = serial_number;
    let bundle = admin.gen_cert()?;
    let main_ca_dir = format!("{}/CA/root", &config.out_dir);
    let filename = format!("admin-{}", bundle.cert.serial_number().to_bn().unwrap());
    let symlink_path = format!("{}/master/admin", &config.out_dir);
    write_bundle_to_file(&bundle, &main_ca_dir, "admin", config.overwrite).unwrap();
    create_symlink("../CA/root", &filename, &symlink_path);
    Ok(bundle)
}

pub fn user_cert(ca: &Box<Bundle>, config: &Config, user: &User, serial_number: u32) -> Result<Box<Bundle>, &'static str> {
    let mut user_cert = CertificateParameters::client(&user.username, config.key_size, config.validity_days);
    user_cert.subject.organization = opt_str(&user.group);
    user_cert.ca = Some(&ca);
    user_cert.serial_number = serial_number;
    let bundle = user_cert.gen_cert()?;
    let outdir = format!("{}/CA/root", &config.out_dir);
    write_bundle_to_file(&bundle, &outdir, &user.username, config.overwrite).unwrap();
    let cn = &bundle.cert.serial_number().to_bn().unwrap();
    let cert_name = format!("{}-{}", &user.username, cn);
    let node_cert_path = format!("{}/users/{}", &config.out_dir, &user.username);
    create_symlink("../CA/root", &cert_name, &node_cert_path);
    Ok(bundle)
}

pub fn apiserver_cert(ca: &Box<Bundle>, config: &Config, serial_number: u32) -> Result<Box<Bundle>, &'static str> {
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
    let bundle = api_server.gen_cert()?;
    let main_ca_dir = format!("{}/CA/root", &config.out_dir);
    let filename = format!("apiserver-{}", bundle.cert.serial_number().to_bn().unwrap());
    let symlink_path = format!("{}/master/apiserver", &config.out_dir);
    write_bundle_to_file(&bundle, &main_ca_dir, "apiserver", config.overwrite).unwrap();
    create_symlink("../CA/root", &filename, &symlink_path);
    Ok(bundle)
}

pub fn apiserver_client_cert(ca: &Box<Bundle>, config: &Config, serial_number: u32) -> Result<Box<Bundle>, &'static str> {
    println!("Creating cert for Kubernetes API server kubelet client");
    let mut api_client = CertificateParameters::client(
        "kube-apiserver-kubelet-client",
        config.key_size,
        config.validity_days,
    );
    api_client.subject.organization = Some("system:masters");
    api_client.ca = Some(&ca);
    api_client.serial_number = serial_number;
    let bundle = api_client.gen_cert()?;
    let main_ca_dir = format!("{}/CA/root", &config.out_dir);
    let filename = format!("apiserver-kubelet-client-{}", bundle.cert.serial_number().to_bn().unwrap());
    let symlink_path = format!("{}/master/apiserver-kubelet-client", &config.out_dir);
    write_bundle_to_file(&bundle, &main_ca_dir, "apiserver-kubelet-client", config.overwrite).unwrap();
    create_symlink("../CA/root", &filename, &symlink_path);
    Ok(bundle)
}

pub fn apiserver_etcd_client_cert(ca: &Box<Bundle>, config: &Config, serial_number: u32) -> Result<Box<Bundle>, &'static str> {
    println!("Creating cert for Kubernetes ETCD client");
    let mut api_client = CertificateParameters::client(
        // If etcd auth enable and apiserver etcd username is not root
        // apiserver can't compact etcd storage
        "root",
        config.key_size,
        config.validity_days,
    );
    api_client.subject.organization = Some("system:masters");
    api_client.ca = Some(&ca);
    api_client.serial_number = serial_number;
    let bundle = api_client.gen_cert()?;
    let etcd_ca_dir = format!("{}/CA/etcd", &config.out_dir);
    let filename = format!("apiserver-etcd-client-{}", bundle.cert.serial_number().to_bn().unwrap());
    let symlink_path = format!("{}/master/apiserver-etcd-client", &config.out_dir);
    write_bundle_to_file(&bundle, &etcd_ca_dir, "apiserver-etcd-client", config.overwrite).unwrap();
    create_symlink("../CA/etcd", &filename, &symlink_path);
    Ok(bundle)
}

pub fn controller_manager_cert(ca: &Box<Bundle>, config: &Config, serial_number: u32) -> Result<Box<Bundle>, &'static str> {
    println!("Creating cert for Kubernetes controller-manager");
    let mut kube_cm = CertificateParameters::client(
        "system:kube-controller-manager",
        config.key_size,
        config.validity_days,
    );
    kube_cm.subject.organization = Some("system:masters");
    kube_cm.serial_number = serial_number;
    kube_cm.ca = Some(&ca);
    let bundle = kube_cm.gen_cert()?;
    let main_ca_dir = format!("{}/CA/root", &config.out_dir);
    let filename = format!("kube-controller-manager-{}", bundle.cert.serial_number().to_bn().unwrap());
    let symlink_path = format!("{}/master/kube-controller-manager", &config.out_dir);
    write_bundle_to_file(&bundle, &main_ca_dir, "kube-controller-manager", config.overwrite).unwrap();
    create_symlink("../CA/root", &filename, &symlink_path);
    Ok(bundle)
}

pub fn scheduler_cert(ca: &Box<Bundle>, config: &Config, serial_number: u32) -> Result<Box<Bundle>, &'static str> {
    println!("Creating cert for Kubernetes scheduler");
    let mut scheduler = CertificateParameters::client(
        "system:kube-scheduler",
        config.key_size,
        config.validity_days,
    );
    scheduler.subject.organization = Some("system:masters");
    scheduler.ca = Some(&ca);
    scheduler.serial_number = serial_number;
    let bundle = scheduler.gen_cert()?;
    let main_ca_dir = format!("{}/CA/root", &config.out_dir);
    let filename = format!("kube-scheduler-{}", bundle.cert.serial_number().to_bn().unwrap());
    let symlink_path = format!("{}/master/kube-scheduler", &config.out_dir);
    write_bundle_to_file(&bundle, &main_ca_dir, "kube-scheduler", config.overwrite).unwrap();
    create_symlink("../CA/root", &filename, &symlink_path);
    Ok(bundle)
}

pub fn proxy_cert(ca: &Box<Bundle>, config: &Config, serial_number: u32) -> Result<Box<Bundle>, &'static str> {
    println!("Creating cert for Kubernetes proxy");
    let mut proxy =
        CertificateParameters::client("system:kube-proxy", config.key_size, config.validity_days);
    proxy.subject.organization = Some("system:node-proxier");
    proxy.serial_number = serial_number;
    proxy.ca = Some(&ca);
    let bundle = proxy.gen_cert()?;
    let main_ca_dir = format!("{}/CA/root", &config.out_dir);
    let filename = format!("kube-proxy-{}", bundle.cert.serial_number().to_bn().unwrap());
    let symlink_path = format!("{}/master/kube-proxy", &config.out_dir);
    write_bundle_to_file(&bundle, &main_ca_dir, "kube-proxy", config.overwrite).unwrap();
    create_symlink("../CA/root", &filename, &symlink_path);
    for worker in config.worker.iter() {
        let mut cert_filename = match worker.filename {
            Some(ref filename) => filename.to_owned(),
            None => worker.hostname.clone(),
        };
        let node_symlink_path = format!("{}/{}/kube-proxy", &config.out_dir, &cert_filename);
        create_symlink("../CA/root", &filename, &node_symlink_path);
    }
    Ok(bundle)
}

pub fn front_proxy_cert(ca: &Box<Bundle>, config: &Config, serial_number: u32) -> Result<Box<Bundle>, &'static str> {
    println!("Creating cert: front-proxy-client");
    let mut fpc =
        CertificateParameters::client("front-proxy-client", config.key_size, config.validity_days);
    fpc.serial_number = serial_number;
    fpc.ca = Some(&ca);
    let bundle = fpc.gen_cert()?;
    let front_ca_dir = format!("{}/CA/front-proxy", &config.out_dir);
    let filename = format!("front-proxy-client-{}", bundle.cert.serial_number().to_bn().unwrap());
    let symlink_path = format!("{}/master/front-proxy-client", &config.out_dir);
    write_bundle_to_file(&bundle, &front_ca_dir, "front-proxy-client", config.overwrite).unwrap();
    create_symlink("../CA/front-proxy", &filename, &symlink_path);
    Ok(bundle)
}

pub fn gen_cert(ca: &CA, config: &Config, cert_type: &CertType) -> Result<Box<Bundle>, &'static str> {
    let root_index_filename = format!("{}/CA/root/index", &config.out_dir);
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
        CertType::EtcdUser(username) => gen_etcd_user(&username, Some(&ca.etcd_ca), &config),
        CertType::Kubelet(ref worker) => gen_kubelet_cert(&worker, Some(&ca.main_ca), &config),
        CertType::KubeletServer(ref worker) => gen_kubelet_server_cert(&worker, Some(&ca.main_ca), &config),
        CertType::User(ref user) => user_cert(&ca.main_ca, &config, &user, sn)
    }
}
