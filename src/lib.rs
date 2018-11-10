extern crate openssl;

use std::fs;
use std::io;
// use std::path::Path;
// use std::fs::OpenOptions;
// use std::io::prelude::*;
use openssl::asn1::Asn1Time;
use openssl::conf::Conf;
use openssl::conf::ConfMethod;
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::PKey;
use openssl::pkey::Private;
use openssl::rsa::Rsa;
use openssl::bn::BigNum;
use openssl::x509::extension::ExtendedKeyUsage;
use openssl::x509::extension::KeyUsage;
use openssl::x509::extension::SubjectAlternativeName;
use openssl::x509::extension::SubjectKeyIdentifier;
use openssl::x509::extension::AuthorityKeyIdentifier;
use openssl::x509::extension::BasicConstraints;
use openssl::x509::X509Extension;
use openssl::x509::{X509Name, X509};

pub struct Bundle {
    pub cert: X509,
    pub key: Vec<u8>,
}

impl Bundle {
    pub fn private_key(&self) -> PKey<Private> {
        PKey::private_key_from_pem(&self.key).expect("Error parsing private key!")
    }

    pub fn to_pem(&self) -> Vec<u8> {
        self.cert.to_pem().expect("Unable to convert cert to X509!")
    }

    pub fn read_from_fs(dir: &str, filename: &str) -> Result<Box<Bundle>, io::Error> {
        let key_filename = format!("{}/{}.key", &dir, &filename);
        let crt_filename = format!("{}/{}.crt", &dir, &filename);

        let key_file = fs::read(&key_filename)?;
        let cert_file = fs::read(&crt_filename)?;

        // let ca_key = Rsa::private_key_from_pem(&key_file).expect("Unable to parse ca.key");
        let ca_cert = X509::from_pem(&cert_file).expect("Unable to parse ca cert.");
        Ok(Box::new(Bundle {
            cert: ca_cert,
            key: key_file,
        }))
    }
}

pub struct CertificateParameters<'a> {
    pub key_length: u32,
    pub serial_number: u32,
    pub validity_days: u32,
    pub subject: Subject<'a>,
    pub key_usage: Vec<&'a str>,
    pub extended_key_usage: Option<Vec<&'a str>>,
    pub basic_constraints: Option<Vec<&'a str>>,
    pub san: Option<Vec<&'a str>>,
    pub ca: Option<&'a Box<Bundle>>,
}

pub struct Subject<'a> {
    pub common_name: &'a str,                    // CN
    pub country: Option<&'a str>,                // C
    pub organization: Option<&'a str>,           // O
    pub organization_unit: Option<&'a str>,       // OU
    pub state_or_province_name: Option<&'a str>,  // ST
    pub locality: Option<&'a str>,               // L
}

impl<'a> CertificateParameters<'a> {
    pub fn default(cn: &str) -> CertificateParameters {
        CertificateParameters {
            key_length: 2048,
            serial_number: 0,
            validity_days: 100,
            subject: Subject {
                common_name: &cn,
                country: None,
                organization: None,
                organization_unit: None,
                state_or_province_name: None,
                locality: None,
            },
            key_usage: vec![],
            extended_key_usage: None,
            basic_constraints: None,
            san: None,
            ca: None,
        }
    }

    pub fn client(cn: &str, key_length: u32, validity_days: u32) -> CertificateParameters {
        CertificateParameters {
            key_length: key_length,
            serial_number: 0,
            validity_days: validity_days,
            subject: Subject {
                common_name: &cn,
                country: None,
                organization: None,
                organization_unit: None,
                state_or_province_name: None,
                locality: None,
            },
            key_usage: vec![
                "digital_signature",
                "key_encipherment",
                "critical",
            ],
            extended_key_usage: Some(vec![
                "client_auth",
            ]),
            basic_constraints: None,
            san: None,
            ca: None,
        }
    }

    pub fn server(cn: &str, key_length: u32, validity_days: u32) -> CertificateParameters {
        CertificateParameters {
            key_length: key_length,
            serial_number: 0,
            validity_days: validity_days,
            subject: Subject {
                common_name: &cn,
                country: None,
                organization: None,
                organization_unit: None,
                state_or_province_name: None,
                locality: None,
            },
            key_usage: vec![
                "digital_signature",
                "key_encipherment",
                "critical",
            ],
            extended_key_usage: Some(vec![
                "server_auth",
            ]),
            basic_constraints: None,
            san: None,
            ca: None,
        }
    }

    pub fn client_and_server(cn: &str, key_length: u32, validity_days: u32) -> CertificateParameters {
        CertificateParameters {
            key_length: key_length,
            serial_number: 0,
            validity_days: validity_days,
            subject: Subject {
                common_name: &cn,
                country: None,
                organization: None,
                organization_unit: None,
                state_or_province_name: None,
                locality: None,
            },
            key_usage: vec![
                "digital_signature",
                "key_encipherment",
                "critical",
            ],
            extended_key_usage: Some(vec![
                "server_auth",
                "client_auth",
            ]),
            basic_constraints: None,
            san: None,
            ca: None,
        }
    }

    pub fn ca(cn: &str, key_length: u32, validity_days: u32) -> CertificateParameters {
        CertificateParameters {
            key_length: key_length,
            serial_number: 0,
            validity_days: validity_days,
            subject: Subject {
                common_name: &cn,
                country: None,
                organization: None,
                organization_unit: None,
                state_or_province_name: None,
                locality: None,
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
        }
    }

    pub fn gen_cert(&self) -> Result<Box<Bundle>, &'static str> {
       //Generate new key for cert
        let rsa = Rsa::generate(self.key_length).unwrap();
        let key = rsa.private_key_to_pem().unwrap();
        let pkey = PKey::from_rsa(rsa).unwrap();
        // Create new certificate builder
        let mut builder = X509::builder().unwrap();
        builder.set_version(2).unwrap();

        // Set public key for cert
        builder.set_pubkey(&pkey).unwrap();

        // Set configuration method for cert
        let conf = Conf::new(ConfMethod::default()).unwrap();

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
            // let extended_usage: X509Extension = eku.build().unwrap();
            let extended_usage = match eku.build() {
                Ok(ex) => ex,
                Err(err) => {
                    println!("Error when build extended key usage:\n{}", err.to_string());
                    return Err("Error!");
                }
            };
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

            if let Some(ref ca) = self.ca {
                let san = san.build(&builder.x509v3_context(Some(&ca.cert), Some(&conf))).unwrap();
                builder.append_extension(san).unwrap();
            } else {
                let san = san.build(&builder.x509v3_context(None, Some(&conf))).unwrap();
                builder.append_extension(san).unwrap();
            }
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
                    _ => &bc,
                };
            }
            let constraints: X509Extension = bc.build().unwrap();
            builder.append_extension(constraints).unwrap();
        }

        // Set key identifiers
        let key_id = SubjectKeyIdentifier::new();
        let mut  issuer_key_id = AuthorityKeyIdentifier::new();
        issuer_key_id.keyid(true);
        if let Some(ref ca) = self.ca {
            let key_ext = key_id.build(&builder.x509v3_context(Some(&ca.cert), Some(&conf))).unwrap();
            let issuer_key_ext = issuer_key_id.build(&builder.x509v3_context(Some(&ca.cert), Some(&conf))).unwrap();
            builder.append_extension(issuer_key_ext).unwrap();
            builder.append_extension(key_ext).unwrap();
        } else {
            let key_ext =               key_id.build(&builder.x509v3_context(None, Some(&conf))).unwrap();
            // Because bug in rust-openssl. No method to set issuer key identifier if cert is self signed.
            // let issuer_key_ext = issuer_key_id.build(&builder.x509v3_context(None, Some(&conf))).unwrap();
            // builder.append_extension(issuer_key_ext).unwrap();
            builder.append_extension(key_ext).unwrap();
        }

        // Sign cert if it not self signed
        if let Some(ref ca) = self.ca {
            builder.set_issuer_name(&ca.cert.subject_name()).unwrap();
            builder.sign(&ca.private_key(), MessageDigest::sha256()).unwrap();
        } else {
            builder.sign(&pkey, MessageDigest::sha256()).unwrap();
            builder.set_issuer_name(&name).unwrap();
        }

        let cert: X509 = builder.build();

        let bundle = Box::new(
            Bundle{
                cert,
                key,
        });
        Ok(bundle)
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
