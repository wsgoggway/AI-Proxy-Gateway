use anyhow::Context;
use rustls::RootCertStore;
use rustls::ServerConfig;
use rustls::pki_types::CertificateDer;
use rustls::server::WebPkiClientVerifier;
use rustls_pemfile::{certs, pkcs8_private_keys};
use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::sync::Arc;
use tokio_rustls::TlsAcceptor;
use x509_parser::prelude::*;

pub fn load_server_config(
    cert_path: &Path,
    key_path: &Path,
    ca_cert_path: Option<&Path>,
) -> anyhow::Result<Arc<ServerConfig>> {
    let cert_file = File::open(cert_path)
        .with_context(|| format!("Failed to open certificate file: {}", cert_path.display()))?;
    let mut cert_reader = BufReader::new(cert_file);
    let cert_chain: Vec<CertificateDer> = certs(&mut cert_reader)
        .collect::<Result<Vec<_>, _>>()
        .context("Failed to read certificate")?;

    let key_file = File::open(key_path)
        .with_context(|| format!("Failed to open key file: {}", key_path.display()))?;
    let mut key_reader = BufReader::new(key_file);
    let private_key = pkcs8_private_keys(&mut key_reader)
        .next()
        .context("Не удалось прочитать приватный ключ")?
        .context("Приватный ключ не найден в файле")?;

    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(private_key);

    let config = if let Some(ca_path) = ca_cert_path {
        let ca_file = File::open(ca_path)
            .with_context(|| format!("Failed to open CA certificate: {}", ca_path.display()))?;
        let mut ca_reader = BufReader::new(ca_file);
        let ca_certs: Vec<CertificateDer> = certs(&mut ca_reader)
            .collect::<Result<Vec<_>, _>>()
            .context("Failed to read CA certificate")?;

        let mut root_store = RootCertStore::empty();
        for cert in ca_certs {
            root_store
                .add(cert)
                .context("Failed to add CA certificate to store")?;
        }

        let client_verifier = WebPkiClientVerifier::builder(Arc::new(root_store))
            .allow_unauthenticated()
            .build()
            .context("Failed to create client cert verifier")?;

        ServerConfig::builder()
            .with_client_cert_verifier(client_verifier)
            .with_single_cert(cert_chain, key)
            .context("Failed to create ServerConfig с mTLS")?
    } else {
        ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(cert_chain, key)
            .context("Failed to create ServerConfig")?
    };

    Ok(Arc::new(config))
}

pub fn build_acceptor(config: Arc<ServerConfig>) -> TlsAcceptor {
    TlsAcceptor::from(config)
}

pub fn extract_user_id_from_cert(cert_der: &CertificateDer) -> Option<String> {
    let (_, cert) = X509Certificate::from_der(cert_der.as_ref()).ok()?;
    let subject = cert.subject();
    for attr in subject.iter_common_name() {
        if let Ok(cn) = attr.attr_value().as_str() {
            return Some(cn.to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{CertificateParams, DnType, IsCa, KeyPair};
    use std::io::Write;
    use std::sync::OnceLock;
    use tempfile::NamedTempFile;

    fn crypto_provider() -> &'static () {
        static INIT: OnceLock<()> = OnceLock::new();
        INIT.get_or_init(|| {
            rustls::crypto::ring::default_provider()
                .install_default()
                .expect("install ring crypto provider");
        })
    }

    fn generate_test_cert_files() -> (NamedTempFile, NamedTempFile) {
        let key_pair = KeyPair::generate().expect("generate key pair");
        let params = CertificateParams::new(["localhost".to_string()]).expect("certificate params");
        let cert = params.self_signed(&key_pair).expect("self-signed cert");

        let mut cert_file = NamedTempFile::new().expect("temp cert file");
        write!(cert_file, "{}", cert.pem()).expect("write cert");
        cert_file.flush().expect("flush cert");

        let mut key_file = NamedTempFile::new().expect("temp key file");
        write!(key_file, "{}", key_pair.serialize_pem()).expect("write key");
        key_file.flush().expect("flush key");

        (cert_file, key_file)
    }

    fn generate_ca_and_client_cert() -> (NamedTempFile, NamedTempFile, NamedTempFile) {
        let ca_key = KeyPair::generate().expect("ca key");
        let mut ca_params = CertificateParams::new(["Test CA".to_string()]).expect("ca params");
        ca_params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "Test CA");
        let ca_cert = ca_params.self_signed(&ca_key).expect("ca cert");

        let mut ca_cert_file = NamedTempFile::new().expect("ca cert file");
        write!(ca_cert_file, "{}", ca_cert.pem()).expect("write ca cert");
        ca_cert_file.flush().expect("flush ca cert");

        let client_key = KeyPair::generate().expect("client key");
        let mut client_params =
            CertificateParams::new(["client".to_string()]).expect("client params");
        client_params
            .distinguished_name
            .push(DnType::CommonName, "user123");
        let client_cert = client_params
            .signed_by(&client_key, &ca_cert, &ca_key)
            .expect("sign client cert");

        let mut client_cert_file = NamedTempFile::new().expect("client cert file");
        write!(client_cert_file, "{}", client_cert.pem()).expect("write client cert");
        client_cert_file.flush().expect("flush client cert");

        let mut client_key_file = NamedTempFile::new().expect("client key file");
        write!(client_key_file, "{}", client_key.serialize_pem()).expect("write client key");
        client_key_file.flush().expect("flush client key");

        (ca_cert_file, client_cert_file, client_key_file)
    }

    #[test]
    fn test_load_server_config_valid() {
        crypto_provider();
        let (cert_file, key_file) = generate_test_cert_files();
        let config = load_server_config(cert_file.path(), key_file.path(), None)
            .expect("load server config");
        assert!(config.max_fragment_size.is_none());
    }

    #[test]
    fn test_load_server_config_with_mtls() {
        crypto_provider();
        let (cert_file, key_file) = generate_test_cert_files();
        let (ca_file, _, _) = generate_ca_and_client_cert();
        let config = load_server_config(cert_file.path(), key_file.path(), Some(ca_file.path()))
            .expect("load server config with mTLS");
        assert!(config.max_fragment_size.is_none());
    }

    #[test]
    fn test_load_server_config_invalid_path() {
        let result = load_server_config(
            Path::new("/nonexistent/cert.pem"),
            Path::new("/nonexistent/key.pem"),
            None,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_build_acceptor() {
        crypto_provider();
        let (cert_file, key_file) = generate_test_cert_files();
        let config = load_server_config(cert_file.path(), key_file.path(), None)
            .expect("load server config");
        let _acceptor = build_acceptor(config);
    }

    #[test]
    fn test_extract_user_id() {
        let (_, client_cert_file, _) = generate_ca_and_client_cert();
        let cert_pem = std::fs::read(client_cert_file.path()).expect("read client cert");
        let certs: Vec<CertificateDer> = rustls_pemfile::certs(&mut cert_pem.as_slice())
            .collect::<Result<Vec<_>, _>>()
            .expect("parse cert");
        let user_id = extract_user_id_from_cert(&certs[0]);
        assert_eq!(user_id, Some("user123".to_string()));
    }

    #[test]
    fn test_extract_user_id_none() {
        let (cert_file, _) = generate_test_cert_files();
        let cert_pem = std::fs::read(cert_file.path()).expect("read cert");
        let certs: Vec<CertificateDer> = rustls_pemfile::certs(&mut cert_pem.as_slice())
            .collect::<Result<Vec<_>, _>>()
            .expect("parse cert");
        // rcgen self-signed cert — CN = "rcgen self signed cert"
        let user_id = extract_user_id_from_cert(&certs[0]);
        assert_eq!(user_id, Some("rcgen self signed cert".to_string()));
    }
}
