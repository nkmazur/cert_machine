#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate gumdrop;
extern crate cert_machine;
extern crate openssl;

mod arg_parser;
mod config_parser;
mod kubernetes_certs;

use kubernetes_certs::opt_str;
use kubernetes_certs::User;
use config_parser::Instance;
use std::collections::HashMap;
use std::io::Write;
use std::os::unix::fs::symlink;
use std::process::exit;
use std::fs::OpenOptions;
use std::fs;
use kubernetes_certs::gen_cert;
use kubernetes_certs::CertType;
use kubernetes_certs::gen_main_ca_cert;
use cert_machine::Bundle;
use kubernetes_certs::gen_ca_cert;
use kubernetes_certs::write_bundle_to_file;
use arg_parser::{CommandOptions, Command};
use config_parser::Config;
use gumdrop::Options;

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

fn create_ca(config: &Config, out_dir: &str) -> Result<CA, &'static str> {
    println!("Creating CA with name: {}", config.cluster_name);
    let main_ca = match gen_main_ca_cert(&config) {
        Ok(bundle) => {
            let outdir = format!("{}/CA/root", &out_dir);
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
            let outdir = format!("{}/CA/etcd", &out_dir);
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
            let outdir = format!("{}/CA/front-proxy", &out_dir);
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

        // println!("Source filename: {}", &source_filename);
        // println!("Destination filename: {}", &dest_filename);

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
                    panic!("Enable to create symlink: {}", err);
                },
            }
        }
    }
}


fn main() {
    let opts = CommandOptions::parse_args_default_or_exit();

    let mut config = Config::new("config.toml");
    // let out_dir = "certs".to_owned();
    let out_dir = match opts.outdir {
        Some(dir) => dir,
        None => "certs".to_owned(),
    };
    config.out_dir = out_dir.to_owned();

    match opts.command {
        Some(Command::New(_)) => {
            kubernetes_certs::create_directory_struct(&config, &out_dir).unwrap();
            let ca = match create_ca(&config, &out_dir) {
                Ok(ca) => ca,
                Err(err) => {
                    panic!("Error when creating certificate authority: {}", err);
                },
            };
            let root_ca_crt_symlink = format!("{}/master/ca.crt", &out_dir);
            let root_ca_key_symlink = format!("{}/master/ca.key", &out_dir);
            let etcd_ca_crt_symlink = format!("{}/master/etcd-ca.crt", &out_dir);
            let front_ca_crt_symlink = format!("{}/master/front-proxy-ca.crt", &out_dir);
            let front_ca_key_symlink = format!("{}/master/front-proxy-ca.key", &out_dir);

            symlink("../CA/root/certs/ca.crt", &root_ca_crt_symlink).unwrap();
            symlink("../CA/root/keys/ca.key", &root_ca_key_symlink).unwrap();
            symlink("../CA/etcd/certs/ca.crt", &etcd_ca_crt_symlink).unwrap();
            symlink("../CA/front-proxy/certs/ca.crt", &front_ca_crt_symlink).unwrap();
            symlink("../CA/front-proxy/keys/ca.key", &front_ca_key_symlink).unwrap();
            for instance in config.worker.iter() {
                let mut cert_filename = match instance.filename {
                    Some(ref filename) => filename.to_owned(),
                    None => instance.hostname.clone(),
                };
                let ca_symlink = format!("{}/{}/ca.crt", &out_dir, &cert_filename);
                symlink("../CA/root/certs/ca.crt", &ca_symlink).unwrap();
                match gen_cert(&ca, &config, &CertType::KubeletServer(&instance)) {
                    Ok(bundle) => {
                        let outdir = format!("{}/CA/root", &config.out_dir);
                        match write_bundle_to_file(&bundle, &outdir, &cert_filename, config.overwrite) {
                            Ok(_) => (),
                            Err(err) => panic!("Error, when writing cert: {}", err),
                        }
                        let sn = &bundle.cert.serial_number().to_bn().unwrap();
                        let cert_name = format!("{}-{}", &cert_filename, sn);
                        let node_cert_path = format!("{}/{}/node", &out_dir, &cert_filename);
                        create_symlink("../CA/root", &cert_name, &node_cert_path);
                    },
                    Err(err) => panic!("Error when generate kubelet cert: {}", err),
                }
                match kubernetes_certs::gen_kubelet_cert(&instance, Some(&ca.main_ca), &config) {
                    Ok(bundle) => {
                        let node_cert_path = format!("{}/{}/node-kubeconfig", &out_dir, &cert_filename);
                        let outdir = format!("{}/CA/root", &config.out_dir);

                        cert_filename.push_str("-kubeconfig");

                        match write_bundle_to_file(&bundle, &outdir, &cert_filename, config.overwrite) {
                            Ok(_) => (),
                            Err(err) => panic!("Error, when writing cert: {}", err),
                        }
                        let sn = &bundle.cert.serial_number().to_bn().unwrap();
                        let cert_name = format!("{}-{}", &cert_filename, sn);
                        create_symlink("../CA/root", &cert_name, &node_cert_path);
                    },
                    Err(err) => panic!("{}", err),
                }
            }

            for instance in config.etcd_server.iter() {
                let mut cert_filename = match instance.filename {
                    Some(ref filename) => filename.to_owned(),
                    None => instance.hostname.clone(),
                };
                let ca_symlink = format!("{}/{}/etcd-ca.crt", &out_dir, &cert_filename);
                symlink("../CA/etcd/certs/ca.crt", &ca_symlink).unwrap();
                match kubernetes_certs::gen_etcd_cert(&instance, Some(&ca.etcd_ca), &config) {
                    Ok(bundle) => {
                        let outdir = format!("{}/CA/etcd", &config.out_dir);
                        write_bundle_to_file(&bundle, &outdir, &cert_filename, config.overwrite).unwrap();
                        let cn = &bundle.cert.serial_number().to_bn().unwrap();
                        let cert_name = format!("{}-{}", &cert_filename, cn);
                        let node_cert_path = format!("{}/{}/etcd", &out_dir, &cert_filename);
                        create_symlink("../CA/etcd", &cert_name, &node_cert_path);
                    },
                    Err(err) => panic!("{}", err),
                }
            }
            kubernetes_certs::kube_certs(&ca, &config, &out_dir);
        },
        Some(Command::InitCa(_)) => {
            match create_ca(&config, &out_dir) {
                Ok(ca) => ca,
                Err(err) => {
                    panic!("Error when creating certificate authority: {}", err);

                },
            };
        },
        Some(Command::GenCert(options)) => {
            let main_ca_dir = format!("{}/CA/root", &out_dir);
            let etcd_ca_dir = format!("{}/CA/etcd", &out_dir);
            let front_ca_dir = format!("{}/CA/front-proxy", &out_dir);
            let ca = CA::read_from_fs(&out_dir);
            match options.kind.as_ref() {
                "admin" => {
                    match gen_cert(&ca, &config, &CertType::Admin) {
                        Ok(bundle) => {
                            let filename = format!("admin-{}", bundle.cert.serial_number().to_bn().unwrap());
                            let symlink_path = format!("{}/master/admin", &out_dir);
                            write_bundle_to_file(&bundle, &main_ca_dir, "admin", config.overwrite).unwrap();
                            create_symlink("../CA/root", &filename, &symlink_path);
                        },
                        Err(err) => panic!("Error: {}", err),
                    }
                },
                "apiserver" => {
                    match gen_cert(&ca, &config, &CertType::ApiServer) {
                        Ok(bundle) => {
                            let filename = format!("apiserver-{}", bundle.cert.serial_number().to_bn().unwrap());
                            let symlink_path = format!("{}/master/apiserver", &out_dir);
                            write_bundle_to_file(&bundle, &main_ca_dir, "apiserver", config.overwrite).unwrap();
                            create_symlink("../CA/root", &filename, &symlink_path);
                        },
                        Err(err) => panic!("Error: {}", err),
                    }
                },
                "apiserver-client" => {
                    match gen_cert(&ca, &config, &CertType::ApiServerClient) {
                        Ok(bundle) => {
                            let filename = format!("apiserver-kubelet-client-{}", bundle.cert.serial_number().to_bn().unwrap());
                            let symlink_path = format!("{}/master/apiserver-kubelet-client", &out_dir);
                            write_bundle_to_file(&bundle, &main_ca_dir, "apiserver-kubelet-client", config.overwrite).unwrap();
                            create_symlink("../CA/root", &filename, &symlink_path);
                        },
                        Err(err) => panic!("Error: {}", err),
                    }
                },
                "apiserver-etcd-client" => {
                    match gen_cert(&ca, &config, &CertType::ApiServerEtcdClient) {
                        Ok(bundle) => {
                            let filename = format!("apiserver-etcd-client-{}", bundle.cert.serial_number().to_bn().unwrap());
                            let symlink_path = format!("{}/master/apiserver-etcd-client", &out_dir);
                            write_bundle_to_file(&bundle, &etcd_ca_dir, "apiserver-etcd-client", config.overwrite).unwrap();
                            create_symlink("../CA/etcd", &filename, &symlink_path);
                        },
                        Err(err) => panic!("Error: {}", err),
                    }
                },
                "controller-manager" => {
                    match gen_cert(&ca, &config, &CertType::ControllerManager) {
                        Ok(bundle) => {
                            let filename = format!("kube-controller-manager-{}", bundle.cert.serial_number().to_bn().unwrap());
                            let symlink_path = format!("{}/master/kube-controller-manager", &out_dir);
                            write_bundle_to_file(&bundle, &main_ca_dir, "kube-controller-manager", config.overwrite).unwrap();
                            create_symlink("../CA/root", &filename, &symlink_path);
                        }
                        Err(err) => panic!("Error: {}", err),
                    }
                },
                "scheduler" => {
                    match gen_cert(&ca, &config, &CertType::Scheduler) {
                        Ok(bundle) => {
                            let filename = format!("kube-scheduler-{}", bundle.cert.serial_number().to_bn().unwrap());
                            let symlink_path = format!("{}/master/kube-scheduler", &out_dir);
                            write_bundle_to_file(&bundle, &main_ca_dir, "kube-scheduler", config.overwrite).unwrap();
                            create_symlink("../CA/root", &filename, &symlink_path);
                        }
                        Err(err) => panic!("Error: {}", err),
                    }
                },
                "front-proxy-client" => {
                    match gen_cert(&ca, &config, &CertType::FrontProxy) {
                        Ok(bundle) => {
                            let filename = format!("front-proxy-client-{}", bundle.cert.serial_number().to_bn().unwrap());
                            let symlink_path = format!("{}/master/front-proxy-client", &out_dir);
                            write_bundle_to_file(&bundle, &front_ca_dir, "front-proxy-client", config.overwrite).unwrap();
                            create_symlink("../CA/front-proxy", &filename, &symlink_path);
                        }
                        Err(err) => panic!("Error: {}", err),
                    }
                },
                "proxy" => {
                    match gen_cert(&ca, &config, &CertType::Proxy) {
                        Ok(bundle) => {
                            let filename = format!("kube-proxy-{}", bundle.cert.serial_number().to_bn().unwrap());
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
                },
                kind if kind.starts_with("kubelet:") => {
                    let hostname = kind.clone().split_at(8);
                    println!("Gen cert for {} node!", hostname.1);

                    let mut instances: HashMap<&str, &Instance> = HashMap::new();
                    for instance in config.worker.iter() {
                        instances.insert(&instance.hostname, &instance);
                    }
                    let instance = match instances.get::<str>(&hostname.1) {
                        Some(instance) => instance,
                        None => {
                            eprintln!("No such kubelet hostname found in config file: {}", &hostname.1);
                            exit(1);
                        },
                    };
                    let mut cert_filename = match instance.filename {
                        Some(ref filename) => filename.to_owned(),
                        None => instance.hostname.clone(),
                    };
                    let node_path = format!("{}/{}", &out_dir, &cert_filename);
                    fs::create_dir_all(&node_path).unwrap();
                    match gen_cert(&ca, &config, &CertType::KubeletServer(&instance)) {
                        Ok(bundle) => {
                            let outdir = format!("{}/CA/root", &config.out_dir);
                            match write_bundle_to_file(&bundle, &outdir, &cert_filename, config.overwrite) {
                                Ok(_) => (),
                                Err(err) => panic!("Error, when writing cert: {}", err),
                            }
                            let sn = &bundle.cert.serial_number().to_bn().unwrap();
                            let cert_name = format!("{}-{}", &cert_filename, sn);
                            let node_cert_path = format!("{}/{}/node", &out_dir, &cert_filename);
                            create_symlink("../CA/root", &cert_name, &node_cert_path);
                        },
                        Err(err) => panic!("Error when generate kubelet cert: {}", err),
                    }
                    match kubernetes_certs::gen_kubelet_cert(&instance, Some(&ca.main_ca), &config) {
                        Ok(bundle) => {
                            let node_cert_path = format!("{}/{}/node-kubeconfig", &out_dir, &cert_filename);
                            let outdir = format!("{}/CA/root", &config.out_dir);

                            cert_filename.push_str("-kubeconfig");

                            match write_bundle_to_file(&bundle, &outdir, &cert_filename, config.overwrite) {
                                Ok(_) => (),
                                Err(err) => panic!("Error, when writing cert: {}", err),
                            }
                            let sn = &bundle.cert.serial_number().to_bn().unwrap();
                            let cert_name = format!("{}-{}", &cert_filename, sn);
                            create_symlink("../CA/root", &cert_name, &node_cert_path);
                        },
                        Err(err) => panic!("{}", err),
                    }
                },
                kind if kind.starts_with("etcd:") => {
                    let hostname = kind.clone().split_at(5);
                    let mut instances: HashMap<&str, &Instance> = HashMap::new();

                    for instance in config.etcd_server.iter() {
                        instances.insert(&instance.hostname, &instance);
                    }
                    let instance = match instances.get::<str>(&hostname.1) {
                        Some(instance) => instance,
                        None => {
                            eprintln!("No such etcd server hostname found in config file: \"{}\"", &hostname.1);
                            exit(1);
                        },
                    };
                    println!("Gen cert for \"{}\" etcd node!", hostname.1);
                    let mut cert_filename = match instance.filename {
                        Some(ref filename) => filename.to_owned(),
                        None => instance.hostname.clone(),
                    };
                    match kubernetes_certs::gen_etcd_cert(&instance, Some(&ca.etcd_ca), &config) {
                        Ok(bundle) => {
                            let outdir = format!("{}/CA/etcd", &config.out_dir);
                            write_bundle_to_file(&bundle, &outdir, &cert_filename, config.overwrite).unwrap();
                            let cn = &bundle.cert.serial_number().to_bn().unwrap();
                            let cert_name = format!("{}-{}", &cert_filename, cn);
                            let node_cert_path = format!("{}/{}/etcd", &out_dir, &cert_filename);
                            let ca_cert_path = format!("{}/{}/etcd-ca.crt", &out_dir, &cert_filename);
                            let output_directory = format!("{}/{}", &out_dir, &cert_filename);
                            fs::create_dir_all(&output_directory).unwrap();
                            create_symlink("../CA/etcd", &cert_name, &node_cert_path);
                            symlink("../CA/etcd/certs/ca.crt", &ca_cert_path).unwrap();
                        },
                        Err(err) => panic!("{}", err),
                    }
                },
                kind if kind.starts_with("etcd-user:") => {
                    let username = kind.clone().split_at(10);

                    println!("Gen cert for \"{}\" etcd user!", username.1);

                    match kubernetes_certs::gen_etcd_user(&username.1, Some(&ca.etcd_ca), &config) {
                        Ok(bundle) => {
                            let outdir = format!("{}/CA/etcd", &config.out_dir);
                            write_bundle_to_file(&bundle, &outdir, &username.1, config.overwrite).unwrap();
                            let cn = &bundle.cert.serial_number().to_bn().unwrap();
                            let cert_name = format!("{}-{}", &username.1, cn);
                            let node_cert_path = format!("{}/users/{}", &out_dir, &username.1);
                            create_symlink("../CA/etcd", &cert_name, &node_cert_path);
                        },
                        Err(err) => panic!("{}", err),
                    }
                },
                _ => println!("No such certificate kind!"),
            }
        },
        Some(Command::User(options)) => {
            print!("Create user cert with name: {}", options.user);
            let ca = CA::read_from_fs(&out_dir);
            match options.group {
                Some(ref group) => println!(" and group: {}", group),
                None => print!("\n"),
            }
            let user = User {
                username: &options.user,
                groups: opt_str(&options.group),
            };
            match gen_cert(&ca, &config, &CertType::User(user)) {
                Ok(bundle) => {
                    let outdir = format!("{}/CA/root", &config.out_dir);
                    write_bundle_to_file(&bundle, &outdir, &options.user, config.overwrite).unwrap();
                    let cn = &bundle.cert.serial_number().to_bn().unwrap();
                    let cert_name = format!("{}-{}", &options.user, cn);
                    let node_cert_path = format!("{}/users/{}", &out_dir, &options.user);
                    create_symlink("../CA/root", &cert_name, &node_cert_path);
                },
                Err(err) => panic!("{}", err),
            }
        },
        None => (),
    }
}
