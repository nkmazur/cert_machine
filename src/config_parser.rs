struct Config {
    cluster_name: String,
    workers: Vec<Instance>,
    etcd_servers: Vec<Instance>,
    validity_days: Option<String>,
    key_size: usize,
}

struct Instance {
    filename: Option<String>,
    hostname: String,
    san: Vec<String>,
}

struct Ca {
    common_name: String,
    country: Option<String>,
    organization: Option<String>,
    organization_unit: Option<String>,
    locality: Option<String>,
    state_or_province_name:Option<String>,
    validity_period: usize,
    key_size: usize,
}
