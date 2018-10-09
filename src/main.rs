extern crate openssl;

// use openssl::asn1::Asn1Integer;
use openssl::asn1::Asn1Time;
// use openssl::conf::Conf;
// use openssl::conf::ConfMethod;
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::PKey;
use openssl::rsa::Rsa;
// use openssl::x509::extension::BasicConstraints;
use openssl::bn::BigNum;
use openssl::x509::extension::ExtendedKeyUsage;
use openssl::x509::extension::KeyUsage;
use openssl::x509::extension::SubjectAlternativeName;
use openssl::x509::extension::BasicConstraints;
use openssl::x509::X509Extension;
use openssl::x509::{X509Name, X509};
use std::fs;

struct CertificateParameters<'a> {
    key_length: u32,
    serial_number: u32,
    validity_days: u32,
    subject: &'a Subject,
    key_usage: Vec<String>,
    extended_key_usage: Option<Vec<String>>,
    basic_constraints: Option<Vec<String>>,
    san: Option<Vec<String>>,
    is_self_signed: bool,
    ca_key: Option<&'a openssl::pkey::PKey<openssl::pkey::Private>>,
    ca_crt: Option<&'a openssl::x509::X509>,
    filename: String,
}

struct Subject {
    common_name: String,                    // CN
    country: Option<String>,                // C
    organization: Option<String>,           // O
    organization_unit: Option<String>,      // OU
    state_or_province_name: Option<String>, // ST
    locality: Option<String>,               // L
}

// This function verifies is SAN an IP or hoatname
fn is_ip(string: &str) -> bool {
    let numbers: Vec<&str> = string.split(".").collect();
    if numbers.len() != 4 {
        return false;
    }
    for octet in numbers {
        match octet.parse::<u32>() {
            Ok(num) => {
                if num > 255 {
                    return false;
                };
            }
            Err(_) => {
                return false;
            }
        }
    }
    true
}

fn gen_cert(config: &CertificateParameters) {
    //Generate new key for cert
    let rsa = Rsa::generate(config.key_length).unwrap();
    let key = rsa.private_key_to_pem().unwrap();
    let pkey = PKey::from_rsa(rsa).unwrap();

    // Create new certificate builder
    let mut builder = X509::builder().unwrap();
    builder.set_version(2).unwrap();

    // Set public key for cert
    builder.set_pubkey(&pkey).unwrap();

    // Add key usage into certificate
    let mut ku = KeyUsage::new();
    for item in config.key_usage.iter() {
        match item.as_ref() {
            "critical" => ku.critical(),
            "digital_signature" => ku.digital_signature(),
            "non_repudiation" => ku.non_repudiation(),
            "key_encipherment" => ku.key_encipherment(),
            "data_encipherment" => ku.data_encipherment(),
            "key_agreement" => ku.key_agreement(),
            "key_cert_sign" => ku.key_cert_sign(),
            "crl_sign" => ku.crl_sign(),
            "encipher_only" => ku.encipher_only(),
            "decipher_only" => ku.decipher_only(),
            _ => &ku,
        };
    }
    let usage: X509Extension = ku.build().unwrap();
    builder.append_extension(usage).unwrap();

    //Add extended key usage to cert
    if let Some(ref extended_usages) = config.extended_key_usage {
        let mut eku = ExtendedKeyUsage::new();
        for item in extended_usages.iter() {
            match item.as_ref() {
                "critical" => eku.critical(),
                "server_auth" => eku.server_auth(),
                "client_auth" => eku.client_auth(),
                "code_signing" => eku.code_signing(),
                "time_stamping" => eku.time_stamping(),
                _ => &eku,
            };
        }
        let extended_usage: X509Extension = eku.build().unwrap();
        builder.append_extension(extended_usage).unwrap();
    }

    //Add subject to certificate
    let mut name = X509Name::builder().unwrap();
    name.append_entry_by_nid(Nid::COMMONNAME, &config.subject.common_name)
        .unwrap();
    if let Some(ref value) = config.subject.country {
        name.append_entry_by_nid(Nid::COUNTRYNAME, &value)
            .unwrap()
    };
    if let Some(ref value) = config.subject.organization {
        name.append_entry_by_nid(Nid::ORGANIZATIONNAME, &value)
            .unwrap()
    };
    if let Some(ref value) = config.subject.organization_unit {
        name.append_entry_by_nid(Nid::ORGANIZATIONALUNITNAME, &value)
            .unwrap()
    };
    if let Some(ref value) = config.subject.state_or_province_name {
        name.append_entry_by_nid(Nid::STATEORPROVINCENAME, &value)
            .unwrap()
    };
    if let Some(ref value) = config.subject.locality {
        name.append_entry_by_nid(Nid::LOCALITYNAME, &value).unwrap()
    };
    let name = name.build();
    builder.set_subject_name(&name).unwrap();

    //Set validity period for cert
    let not_before = Asn1Time::days_from_now(0).unwrap();
    let not_after = Asn1Time::days_from_now(config.validity_days).unwrap();
    builder.set_not_before(&not_before).unwrap();
    builder.set_not_after(&not_after).unwrap();

    // Set alternative names to cert
    if let Some(ref alternative_names) = config.san {
        let mut san = SubjectAlternativeName::new();
        for name in alternative_names.iter() {
            match is_ip(&name) {
                true => san.ip(&name),
                false => san.dns(&name),
            };
        }
        // let san = san.build(&builder.x509v3_context(Some(&ca_cert), Some(&conf))).unwrap();
        let san = san.build(&builder.x509v3_context(None, None)).unwrap();
        builder.append_extension(san).unwrap();

    }

    // Set serial number
    let serial_number = BigNum::from_u32(config.serial_number).unwrap();
    let serial_number = serial_number.as_ref().to_asn1_integer().unwrap();
    builder.set_serial_number(&serial_number).unwrap();

    // Set basic constraints
    let mut bc = BasicConstraints::new();
    bc.critical();
    if let Some(ref constraints) = config.basic_constraints {
        for constraint in constraints.iter() {
            match constraint.as_ref() {
                "ca" => bc.ca(),
                // "critical" => bc.critical(),
                _ => &bc,
            };
        }
        let constraints: X509Extension = bc.build().unwrap();
        builder.append_extension(constraints).unwrap();
    }

    // Sign cert if it not self signed
    if config.is_self_signed != true {
        if let Some(ca_cert) = config.ca_crt {
            let ca_subject = ca_cert.subject_name();
            builder.set_issuer_name(ca_subject).unwrap();
        }

        if let Some(ca_key) = config.ca_key {
            builder.sign(&ca_key, MessageDigest::sha256()).unwrap();
        }
    } else {
        builder.sign(&pkey, MessageDigest::sha256()).unwrap();
        builder.set_issuer_name(&name).unwrap();
    }

    let certificate: X509 = builder.build();

    let pem = certificate.to_pem().unwrap();

    let crt_filename = format!("{}.crt",config.filename);
    let key_filename = format!("{}.key",config.filename);

    fs::write(crt_filename, pem).expect("Unable to write file!");
    fs::write(key_filename, key).expect("Unable to write file!");
}

fn main() {
    let ca_subject = Subject {
        common_name: "Kubernetes CA".to_owned(),
        country: Some("LV".to_owned()),
        organization: Some("Containerum".to_owned()),
        organization_unit: Some("IFR".to_owned()),
        state_or_province_name: None,
        locality: None,
    };

    let ca_cert = CertificateParameters {
        key_length: 2048,
        serial_number: 1,
        validity_days: 1000,
        subject: &ca_subject,
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
        filename: "ca".to_owned(),
    };

    gen_cert(&ca_cert);

    let ca_key_file = fs::read("ca.key").expect("Unable to open ca.key");
    let ca_key = PKey::private_key_from_pem(&ca_key_file).expect("Unable to parse ca.key");

    let ca_cert_file = fs::read("ca.crt").expect("Unable to open ca.crt");
    let ca_cert = X509::from_pem(&ca_cert_file).expect("Unable to parse ca.crt");

    let subject = Subject {
        common_name: "kubernetes".to_owned(),
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
        subject: &subject,
        key_usage: vec![
            "digital_signature".to_owned(),
            "key_encipherment".to_owned(),
            "critical".to_owned(),
        ],
        extended_key_usage: Some(vec!["server_auth".to_owned()]),
        basic_constraints: None,
        san: Some(vec![
            "kubernetes".to_owned(),
            "kubernetes.default".to_owned(),
            "kubernetes.default".to_owned(),
            "kubernetes.default.svc.cluster.local".to_owned(),
            "10.96.0.1".to_owned(),
        ]),
        is_self_signed: false,
        ca_key: Some(&ca_key),
        ca_crt: Some(&ca_cert),
        filename: "cert".to_owned(),
    };
 
    gen_cert(&cert);
}
