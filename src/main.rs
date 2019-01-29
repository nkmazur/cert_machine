#[macro_use]
extern crate serde_derive;
extern crate cert_machine;
extern crate openssl;
extern crate clap;

// mod arg_parser;
mod config_parser;
mod kubernetes_certs;
mod kubeconfig;

use config_parser::User;
use config_parser::Instance;
use std::collections::HashMap;
use std::io::Write;
use std::os::unix::fs::symlink;
use std::process::exit;
use std::fs::OpenOptions;
use std::fs;
use std::path::Path;
use kubernetes_certs::gen_cert;
use kubernetes_certs::CertType;
use kubernetes_certs::gen_main_ca_cert;
use cert_machine::Bundle;
use kubernetes_certs::gen_ca_cert;
use kubernetes_certs::write_bundle_to_file;
use config_parser::Config;
use clap::{App, Arg, SubCommand, AppSettings};

pub struct CA {
    pub main_ca: Box<Bundle>,
    pub etcd_ca: Box<Bundle>,
    pub front_ca: Box<Bundle>,
}

impl CA {
    fn read_from_fs(dir: &str) -> CA {
        let main_ca_dir = format!("{}/CA/root", &dir);
        let etcd_ca_dir = format!("{}/CA/etcd", &dir);
        let front_ca_dir = format!("{}/CA/front-proxy", &dir);
        CA {
            main_ca: Bundle::read_from_fs(&main_ca_dir, "ca").unwrap(),
            etcd_ca: Bundle::read_from_fs(&etcd_ca_dir, "ca").unwrap(),
            front_ca: Bundle::read_from_fs(&front_ca_dir, "ca").unwrap(),
        }
    }
}

fn create_ca(config: &Config) -> Result<CA, &'static str> {
    println!("Creating CA with name: {}", config.cluster_name);
    let main_ca = match gen_main_ca_cert(&config) {
        Ok(bundle) => {
            let outdir = format!("{}/CA/root", &config.out_dir);
            let index_filename = format!("{}/index", &outdir);
            let mut file = OpenOptions::new().write(true)
                                     .create_new(true)
                                     .open(&index_filename)
                                     .unwrap();
            let sn: u32 = 0;
            file.write_all(sn.to_string().as_bytes()).unwrap();
            write_bundle_to_file(&bundle, &outdir, "ca", config.overwrite).unwrap();
            bundle
        },
        Err(error) => return Err(error),
    };

    println!("Create CA: etcd");
    let etcd_ca = match gen_ca_cert("etcd", Some(&main_ca), &config) {
        Ok(bundle) => {
            let outdir = format!("{}/CA/etcd", &config.out_dir);
            let index_filename = format!("{}/index", &outdir);
            let mut file = OpenOptions::new().write(true)
                                     .create_new(true)
                                     .open(&index_filename)
                                     .unwrap();
            let sn: u32 = 0;
            file.write_all(sn.to_string().as_bytes()).unwrap();
            write_bundle_to_file(&bundle, &outdir,"ca", config.overwrite).unwrap();
            bundle
            },
        Err(error) => return Err(error),
    };

    println!("Create CA: front proxy");
    let front_ca = match gen_ca_cert("front-proxy-ca", Some(&main_ca), &config) {
        Ok(bundle) => {
            let outdir = format!("{}/CA/front-proxy", &config.out_dir);
            let index_filename = format!("{}/index", &outdir);
            let mut file = OpenOptions::new().write(true)
                                     .create_new(true)
                                     .open(&index_filename)
                                     .unwrap();
            let sn: u32 = 0;
            file.write_all(sn.to_string().as_bytes()).unwrap();
            write_bundle_to_file(&bundle, &outdir, "ca", config.overwrite).unwrap();
            bundle
        },
        Err(error) => return Err(error),

    };

    let root_ca_crt_symlink = format!("{}/master/ca.crt", &config.out_dir);
    let root_ca_key_symlink = format!("{}/master/ca.key", &config.out_dir);
    let etcd_ca_crt_symlink = format!("{}/master/etcd-ca.crt", &config.out_dir);
    let front_ca_crt_symlink = format!("{}/master/front-proxy-ca.crt", &config.out_dir);
    let front_ca_key_symlink = format!("{}/master/front-proxy-ca.key", &config.out_dir);

    symlink("../CA/root/certs/ca.crt", &root_ca_crt_symlink).unwrap();
    symlink("../CA/root/keys/ca.key", &root_ca_key_symlink).unwrap();
    symlink("../CA/etcd/certs/ca.crt", &etcd_ca_crt_symlink).unwrap();
    symlink("../CA/front-proxy/certs/ca.crt", &front_ca_crt_symlink).unwrap();
    symlink("../CA/front-proxy/keys/ca.key", &front_ca_key_symlink).unwrap();

    Ok(CA {
        main_ca,
        etcd_ca,
        front_ca,
    })
}

fn create_symlink(ca_dir: &str, cert_name: &str, dest: &str) {
    let types = vec![("key", "keys"), ("crt", "certs")];
    for postfix in types.iter() {
        let source_filename = format!("{}/{}/{}.{}", &ca_dir, &postfix.1, &cert_name, &postfix.0);
        let dest_filename = format!("{}.{}", &dest, &postfix.0);

        if let Err(_) =  symlink(&source_filename, &dest_filename) {
            match fs::symlink_metadata(&dest_filename) {
                Ok(ref metadata) => {
                    match metadata.file_type().is_symlink() {
                        true => {
                            fs::remove_file(&dest_filename).unwrap();
                            symlink(&source_filename, &dest_filename).unwrap();
                        },
                        false => {
                            eprintln!("Unable to create symlink. \"{}\" exists and not a symlink!", &dest_filename);
                            exit(1);
                        },
                    }
                },
                Err(err) => {
                    panic!("Unable to create symlink: {}", err);
                },
            }
        }
    }
}

fn main() {
    let matches = App::new("cert-machine")
        .about("TLS certificates generation tool for kubernetes")
        .version("1.0")
		.setting(AppSettings::SubcommandRequiredElseHelp)
        .setting(AppSettings::DisableHelpSubcommand)
        .setting(AppSettings::VersionlessSubcommands)
        .arg(Arg::with_name("config")
        	.short("c")
            .long("config")
            .value_name("FILE")
            .default_value("config.toml")
            .help("Sets a custom config file")
            .takes_value(true))
        .arg(Arg::with_name("outdir")
        	.short("o")
            .long("outdir")
            .value_name("DIR")
            .help("Sets an output directory")
            .takes_value(true))
        .subcommand(SubCommand::with_name("new")
            .about("Creates new CA and certificates"))
        .subcommand(SubCommand::with_name("gen-cert")
            .about("Create new certificate for something")
            .arg(Arg::with_name("kind")
                .required(true)
                .possible_values(&["admin",
                                   "apiserver",
                                   "apiserver-client",
                                   "apiserver-etcd-client",
                                   "controller-manager",
                                   "scheduler",
                                   "front-proxy-client",
                                   "proxy",
                                   "kubelet",
                                   "etcd",
                                   "etcd-user",
                                   "user"])
                .help("kind of certificate"))
            .arg(Arg::with_name("name")
                .required_if("kind", "kubelet")
                .required_if("kind", "etcd-user")
                .required_if("kind", "user")
                .required_if("kind", "etcd")
                .help("name of instance or username"))
            .arg(Arg::with_name("group")
                .help("group for user")))
        .get_matches();

        let config_filename = matches.value_of("config").unwrap();
        let mut config = Config::new(&config_filename);
        if let Some(opts_outdir) = matches.value_of("outdir") {
            config.out_dir = opts_outdir.to_owned();
        }

    match matches.subcommand() {
        ("new", Some(_args)) => {
            let ca_dir = format!("{}/CA", &config.out_dir);
            if Path::new(&ca_dir).exists() {
                eprintln!("CA alredy exists in directory: {}", &config.out_dir);
                exit(1);
            }
            kubernetes_certs::create_directory_struct(&config, &config.out_dir).unwrap();

            let ca = match create_ca(&config) {
                Ok(ca) => ca,
                Err(err) => {
                    panic!("Error when creating certificate authority: {}", err);
                },
            };

            kubernetes_certs::kube_certs(&ca, &config, &config.out_dir);

            for instance in config.worker.iter() {
                let mut cert_filename = match instance.filename {
                    Some(ref filename) => filename.to_owned(),
                    None => instance.hostname.clone(),
                };
                let ca_symlink = format!("{}/{}/ca.crt", &config.out_dir, &cert_filename);
                symlink("../CA/root/certs/ca.crt", &ca_symlink).unwrap();
                gen_cert(&ca, &config, &CertType::Kubelet(&instance)).unwrap();
                gen_cert(&ca, &config, &CertType::KubeletServer(&instance)).unwrap();
            }

            for instance in config.etcd_server.iter() {
                let mut cert_filename = match instance.filename {
                    Some(ref filename) => filename.to_owned(),
                    None => instance.hostname.clone(),
                };
                let ca_symlink = format!("{}/{}/etcd-ca.crt", &config.out_dir, &cert_filename);
                symlink("../CA/etcd/certs/ca.crt", &ca_symlink).unwrap();

                gen_cert(&ca, &config, &CertType::EtcdServer(&instance)).unwrap();
            }
            if let Some(ref users) = config.user {
                for user in users {
                    println!("Creating cert for kubernetes user: {}", &user.username);
                    gen_cert(&ca, &config, &CertType::User(&user)).unwrap();
                }
            }
            if let Some(ref users) = config.etcd_users {
                for user in users {
                    println!("Creating cert for etcd user: {}", &user);
                    gen_cert(&ca, &config, &CertType::EtcdUser(&user)).unwrap();
                }
            }
        },
        ("gen-cert", Some(args)) =>{
            let ca = CA::read_from_fs(&config.out_dir);
            match args.value_of("kind").unwrap() {
                "admin" => {
                    gen_cert(&ca, &config, &CertType::Admin).unwrap();
                    ()
                },
                "apiserver" => {
                    gen_cert(&ca, &config, &CertType::ApiServer).unwrap();
                    ()
                },
                "apiserver-client" => {
                    gen_cert(&ca, &config, &CertType::ApiServerClient).unwrap();
                    ()
                },
                "apiserver-etcd-client" => {
                    gen_cert(&ca, &config, &CertType::ApiServerEtcdClient).unwrap();
                    ()
                },
                "controller-manager" => {
                    gen_cert(&ca, &config, &CertType::ControllerManager).unwrap();
                    ()
                },
                "scheduler" => {
                    gen_cert(&ca, &config, &CertType::Scheduler).unwrap();
                    ()
                },
                "front-proxy-client" => {
                    gen_cert(&ca, &config, &CertType::FrontProxy).unwrap();
                    ()
                },
                "proxy" => {
                    gen_cert(&ca, &config, &CertType::Proxy).unwrap();
                    ()
                },
                "kubelet" => {
                    let hostname = args.value_of("name").unwrap();
                    println!("Gen cert for {} node!", &hostname);

                    let mut instances: HashMap<&str, &Instance> = HashMap::new();
                    for instance in config.worker.iter() {
                        instances.insert(&instance.hostname, &instance);
                    }
                    let instance = match instances.get::<str>(&hostname) {
                        Some(instance) => instance,
                        None => {
                            eprintln!("No such kubelet hostname found in config file: {}", &hostname);
                            exit(1);
                        },
                    };
                    let mut cert_filename = match instance.filename {
                        Some(ref filename) => filename.to_owned(),
                        None => instance.hostname.clone(),
                    };
                    let node_path = format!("{}/{}", &config.out_dir, &cert_filename);
                    fs::create_dir_all(&node_path).unwrap();
                    gen_cert(&ca, &config, &CertType::Kubelet(&instance)).unwrap();
                    gen_cert(&ca, &config, &CertType::KubeletServer(&instance)).unwrap();
                    ()
                },
                "etcd" => {
                    let hostname = args.value_of("name").unwrap();
                    let mut instances: HashMap<&str, &Instance> = HashMap::new();

                    for instance in config.etcd_server.iter() {
                        instances.insert(&instance.hostname, &instance);
                    }
                    let instance = match instances.get::<str>(&hostname) {
                        Some(instance) => instance,
                        None => {
                            eprintln!("No such etcd server hostname found in config file: \"{}\"", &hostname);
                            exit(1);
                        },
                    };
                    println!("Gen cert for \"{}\" etcd node!", hostname);
                    gen_cert(&ca, &config, &CertType::EtcdServer(&instance)).unwrap();
                    ()
                },
                "etcd-user" => {
                    let username = args.value_of("name").unwrap();
                    println!("Gen cert for \"{}\" etcd user!", username);
                    gen_cert(&ca, &config, &CertType::EtcdUser(&username)).unwrap();
                    ()
                },
                "user" => {
                    let username = args.value_of("name").unwrap();
                    let mut group: Option<String> = None;
                    // let group = args.value_of("group").to_owned();
                    print!("Create user cert with name: {}", &username);
                    let ca = CA::read_from_fs(&config.out_dir);
                    match args.value_of("group") {
                        Some(group_name) => {
                            println!(" and group: {}", &group_name);
                            group = Some(group_name.to_owned());
                        },
                        None => print!("\n"),
                    }
                    let user = User {
                        username: username.to_string(),
                        group: group,
                    };
                    gen_cert(&ca, &config, &CertType::User(&user)).unwrap();
                },
                _ => eprintln!("Error!"),
            }
        },
        _ => unreachable!(),
    }
}
