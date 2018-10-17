extern crate openssl;

use openssl::asn1::Asn1Time;
// use openssl::conf::Conf;
// use openssl::conf::ConfMethod;
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::PKey;
use openssl::rsa::Rsa;
use openssl::bn::BigNum;
use openssl::x509::extension::ExtendedKeyUsage;
use openssl::x509::extension::KeyUsage;
use openssl::x509::extension::SubjectAlternativeName;
use openssl::x509::extension::BasicConstraints;
use openssl::x509::X509Extension;
use openssl::x509::{X509Name, X509};
use std::fs;

pub struct CertificateParameters<'a> {
    pub key_length: u32,
    pub serial_number: u32,
    pub validity_days: u32,
    pub subject: Subject<'a>,
    pub key_usage: Vec<String>,
    pub extended_key_usage: Option<Vec<String>>,
    pub basic_constraints: Option<Vec<String>>,
    pub san: Option<Vec<&'a str>>,
    pub is_self_signed: bool,
    pub ca_key: Option<&'a openssl::pkey::PKey<openssl::pkey::Private>>,
    pub ca_crt: Option<&'a openssl::x509::X509>,
    pub filename: &'a str,
}

pub struct Subject<'a> {
    pub common_name: &'a str,                    // CN
    pub country: Option<&'a str>,                // C
    pub organization: Option<&'a str>,           // O
    pub organization_unit: Option<&'a str>,      // OU
    pub state_or_province_name: Option<&'a str>, // ST
    pub locality: Option<&'a str>,               // L
}

impl<'a> CertificateParameters<'a> {
    pub fn default(cn: &str) -> CertificateParameters {
        let subject = Subject {
            common_name: &cn,
            country: None,
            organization: None,
            organization_unit: None,
            state_or_province_name: None,
            locality: None,
        };

        let cert = CertificateParameters {
            key_length: 2048,
            serial_number: 0, //?
            validity_days: 100, //?
            subject: subject,
            key_usage: vec![
            ],
            extended_key_usage: None,
            basic_constraints: None,
            san: None,
            is_self_signed: true,
            ca_key: None,
            ca_crt: None,
            filename: "set me",
        };
        cert
    }

    pub fn gen_cert(&self) -> (X509, PKey<openssl::pkey::Private>) {
        //Generate new key for cert
        let rsa = Rsa::generate(self.key_length).unwrap();
        let key = rsa.private_key_to_pem().unwrap();
        let pkey = PKey::from_rsa(rsa).unwrap();

        // Create new certificate builder
        let mut builder = X509::builder().unwrap();
        builder.set_version(2).unwrap();

        // Set public key for cert
        builder.set_pubkey(&pkey).unwrap();

        // Add key usage into certificate
        let mut ku = KeyUsage::new();
        for item in self.key_usage.iter() {
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
        if let Some(ref extended_usages) = self.extended_key_usage {
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
        name.append_entry_by_nid(Nid::COMMONNAME, &self.subject.common_name)
            .unwrap();
        if let Some(ref value) = self.subject.country {
            name.append_entry_by_nid(Nid::COUNTRYNAME, &value)
                .unwrap()
        };
        if let Some(ref value) = self.subject.organization {
            name.append_entry_by_nid(Nid::ORGANIZATIONNAME, &value)
                .unwrap()
        };
        if let Some(ref value) = self.subject.organization_unit {
            name.append_entry_by_nid(Nid::ORGANIZATIONALUNITNAME, &value)
                .unwrap()
        };
        if let Some(ref value) = self.subject.state_or_province_name {
            name.append_entry_by_nid(Nid::STATEORPROVINCENAME, &value)
                .unwrap()
        };
        if let Some(ref value) = self.subject.locality {
            name.append_entry_by_nid(Nid::LOCALITYNAME, &value).unwrap()
        };
        let name = name.build();
        builder.set_subject_name(&name).unwrap();

        //Set validity period for cert
        let not_before = Asn1Time::days_from_now(0).unwrap();
        let not_after = Asn1Time::days_from_now(self.validity_days).unwrap();
        builder.set_not_before(&not_before).unwrap();
        builder.set_not_after(&not_after).unwrap();

        // Set alternative names to cert
        if let Some(ref alternative_names) = self.san {
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
        let serial_number = BigNum::from_u32(self.serial_number).unwrap();
        let serial_number = serial_number.as_ref().to_asn1_integer().unwrap();
        builder.set_serial_number(&serial_number).unwrap();

        // Set basic constraints
        let mut bc = BasicConstraints::new();
        bc.critical();
        if let Some(ref constraints) = self.basic_constraints {
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
        if self.is_self_signed != true {
            if let Some(ca_cert) = self.ca_crt {
                let ca_subject = ca_cert.subject_name();
                builder.set_issuer_name(ca_subject).unwrap();
            }

            if let Some(ca_key) = self.ca_key {
                builder.sign(&ca_key, MessageDigest::sha256()).unwrap();
            }
        } else {
            builder.sign(&pkey, MessageDigest::sha256()).unwrap();
            builder.set_issuer_name(&name).unwrap();
        }

        let certificate: X509 = builder.build();

        let pem = certificate.to_pem().unwrap();

        let crt_filename = format!("certs/{}.crt",self.filename);
        let key_filename = format!("certs/{}.key",self.filename);

        fs::write(crt_filename, pem).expect("Unable to write file!");
        fs::write(key_filename, key).expect("Unable to write file!");

        (certificate, pkey)
    }
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


