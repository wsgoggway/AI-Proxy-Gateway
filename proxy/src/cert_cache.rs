use lru::LruCache;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};
use tracing::{error, info};

use crate::ca::CertificateAuthority;

/// Maximum number of cached domain certificates (LRU eviction).
const CERT_CACHE_MAX: usize = 256;

type CertEntry = (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>);

pub struct CertCache {
    cache: Mutex<LruCache<String, Arc<CertEntry>>>,
    pub ca: Arc<CertificateAuthority>,
}

impl CertCache {
    pub fn new(ca: Arc<CertificateAuthority>) -> Self {
        Self {
            cache: Mutex::new(LruCache::new(NonZeroUsize::new(CERT_CACHE_MAX).unwrap())),
            ca,
        }
    }

    /// Get or generate a certificate for domain. Returns error if signing fails.
    pub async fn get_or_sign(&self, domain: &str) -> Result<Arc<CertEntry>, String> {
        {
            let mut cache = self.cache.lock().unwrap();
            if let Some(entry) = cache.get(domain) {
                return Ok(entry.clone());
            }
        }
        info!("cert_generate domain={}", domain);
        let entry = self.ca.sign_domain(domain).map_err(|e| {
            let msg = format!("Failed to sign cert for {}: {}", domain, e);
            error!("{}", msg);
            msg
        })?;
        let entry = Arc::new(entry);
        let mut cache = self.cache.lock().unwrap();
        cache.put(domain.to_string(), entry.clone());
        crate::metrics::CERT_CACHE_ENTRIES.set(cache.len() as i64);
        Ok(entry)
    }
}
