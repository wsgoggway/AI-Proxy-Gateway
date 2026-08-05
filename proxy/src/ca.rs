use anyhow::Context;
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::path::Path;
use std::sync::Arc;
use time::OffsetDateTime;
use tracing::{info, warn};

pub struct CertificateAuthority {
    pub ca_pem: String,
    signer: Arc<KeyPair>,
    issuer_cert: rcgen::Certificate,
}

impl CertificateAuthority {
    pub fn load_or_generate(cert_path: &Path, key_path: &Path) -> anyhow::Result<Self> {
        if cert_path.exists() && key_path.exists() {
            info!("ca_load path={}", cert_path.display());
            Self::load(cert_path, key_path)
        } else {
            warn!("═══════════════════════════════════════════");
            warn!("ca_generated action=install_required");
            warn!("ca_install_instruction");
            warn!(
                "  Arch: sudo cp {} /etc/ca-certificates/trust-source/anchors/ai-proxy-ca.crt && sudo trust extract-compat",
                cert_path.display()
            );
            warn!(
                "  Debian/Ubuntu: sudo cp {} /usr/local/share/ca-certificates/ai-proxy-ca.crt && sudo update-ca-certificates",
                cert_path.display()
            );
            warn!(
                "  macOS: sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain {}",
                cert_path.display()
            );
            warn!(
                "  Node.js: export NODE_EXTRA_CA_CERTS={}",
                cert_path.display()
            );
            warn!("═══════════════════════════════════════════");
            let ca = Self::generate()?;
            ca.save(cert_path, key_path)?;
            Ok(ca)
        }
    }

    fn generate() -> anyhow::Result<Self> {
        let key_pair = KeyPair::generate().context("generate CA key")?;

        let mut params = CertificateParams::default();
        params
            .distinguished_name
            .push(DnType::CommonName, "AI Proxy CA");
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.not_before = OffsetDateTime::now_utc();
        params.not_after = OffsetDateTime::now_utc() + time::Duration::days(3650);

        let ca_cert = params.self_signed(&key_pair).context("self-sign")?;
        let pem = ca_cert.pem();

        Ok(Self {
            ca_pem: pem,
            signer: Arc::new(key_pair),
            issuer_cert: ca_cert,
        })
    }

    fn load(cert_path: &Path, key_path: &Path) -> anyhow::Result<Self> {
        let ca_pem = std::fs::read_to_string(cert_path)?;

        let key_pair = KeyPair::from_pem(&std::fs::read_to_string(key_path)?)
            .context("load key pair for signing")?;

        let mut ip = CertificateParams::default();
        ip.distinguished_name
            .push(DnType::CommonName, "AI Proxy CA");
        ip.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let issuer_cert = ip.self_signed(&key_pair)?;

        Ok(Self {
            ca_pem,
            signer: Arc::new(key_pair),
            issuer_cert,
        })
    }

    fn save(&self, cert_path: &Path, key_path: &Path) -> anyhow::Result<()> {
        if let Some(p) = cert_path.parent() {
            std::fs::create_dir_all(p)?;
        }
        std::fs::write(cert_path, &self.ca_pem)?;
        std::fs::write(key_path, self.signer.serialize_pem())?;
        Ok(())
    }

    pub fn sign_domain(
        &self,
        domain: &str,
    ) -> anyhow::Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
        let kp = KeyPair::generate()?;
        let mut params = CertificateParams::new(vec![domain.to_string()])?;
        params.distinguished_name.push(DnType::CommonName, domain);
        params.not_before = OffsetDateTime::now_utc();
        params.not_after = OffsetDateTime::now_utc() + time::Duration::days(397);

        let issuer = &self.issuer_cert;
        let cert = params.signed_by(&kp, issuer, &self.signer)?;

        let cert_der = CertificateDer::from(cert.der().to_vec());
        let key_pem = kp.serialize_pem();
        let key_der: PrivateKeyDer = rustls_pemfile::private_key(&mut key_pem.as_bytes())
            .context("parse domain key")?
            .context("no domain key")?;

        Ok((vec![cert_der], key_der))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_generate() {
        let ca = CertificateAuthority::generate().unwrap();
        assert!(ca.ca_pem.starts_with("-----BEGIN CERTIFICATE-----"));
    }

    #[test]
    fn test_sign_domain() {
        let ca = CertificateAuthority::generate().unwrap();
        let cert = ca.sign_domain("api.deepseek.com").unwrap();
        assert!(!cert.0.is_empty());
    }

    #[test]
    fn test_save_and_load() {
        let dir = TempDir::new().unwrap();
        let cp = dir.path().join("ca.pem");
        let kp = dir.path().join("ca.key");
        let ca = CertificateAuthority::generate().unwrap();
        ca.save(&cp, &kp).unwrap();
        let loaded = CertificateAuthority::load(&cp, &kp).unwrap();
        assert!(loaded.ca_pem.starts_with("-----BEGIN CERTIFICATE-----"));
    }
}
