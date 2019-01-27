extern crate serde_yaml;
extern crate base64;

use std::path::Path;
use std::io;
use std::fs;
use self::base64::encode;
use Bundle;

#[derive(Debug, Serialize)]
struct Kubeconfig<'a> {
    #[serde(rename = "apiVersion")]
	api_vesrsion: &'a str,
	clusters: Vec<Cluster<'a>>,
	contexts: Vec<Context<'a>>,
    #[serde(rename = "current-context")]
	current_context: &'a str,
	kind: &'a str,
	users: Vec<User<'a>>,
}

#[derive(Debug, Serialize)]
struct Cluster<'a> {
	cluster: ClusterParameters<'a>,
	name: &'a str,
}

#[derive(Debug, Serialize)]
struct ClusterParameters<'a> {
    #[serde(rename = "certificate-authority-data")]
    certificate_authority_data: String,
    server: &'a str,
}

#[derive(Debug, Serialize)]
struct Context<'a> {
	context: ContextParameters<'a>,
	name: &'a str,
}

#[derive(Debug, Serialize)]
struct ContextParameters<'a> {
    cluster: &'a str,
    user: &'a str,
}

#[derive(Debug, Serialize)]
struct User<'a> {
    user: UserParameters<'a>,
	name: &'a str,
}

#[derive(Debug, Serialize)]
struct UserParameters<'a> {
    #[serde(rename = "client-certificate-data")]
    client_certificate_data: &'a str,
    #[serde(rename = "client-key-data")]
    client_key_data: &'a str,
}

pub struct KubeconfigParameters<'a> {
    pub apiserver_address: &'a str,
    pub cluster_name: &'a str,
    pub username: &'a str,
    pub cert: &'a Box<Bundle>,
    pub ca_cert: &'a Box<Bundle>,
    pub kubeconfig_filename: &'a str,
}

pub fn create_kubeconfig(config: &KubeconfigParameters) -> Result<String, io::Error> {
    let apiserver_address = format!("https://{}", &config.apiserver_address);
    let client_certificate_data = encode(&config.cert.cert.to_pem().unwrap());
    let client_key_data = encode(&config.cert.key);
    let kubeconfig = Kubeconfig {
		api_vesrsion: "v1",
		clusters: vec![
			Cluster {
				cluster: ClusterParameters {
                    certificate_authority_data: encode(&config.ca_cert.cert.to_pem().unwrap()),
                    server: &apiserver_address,
                },
				name: config.cluster_name.clone(),
			}
		],
		contexts: vec![
			Context {
				context: ContextParameters {
                    cluster: config.cluster_name.clone(),
                    user: config.username.clone(),
                },
				name: "default",
			}
		],
		current_context: "default",
		kind: "Config",
		users: vec![
			User {
				name: config.username.clone(),
                user: UserParameters {
                    client_certificate_data: &client_certificate_data,
                    client_key_data: &client_key_data,
                },
			}
		],
    };

    let kubeconfig_yaml = serde_yaml::to_string(&kubeconfig).unwrap();
    let path = Path::new(&config.kubeconfig_filename);
    fs::write(&path, &kubeconfig_yaml).unwrap();
    Ok(kubeconfig_yaml)
}
