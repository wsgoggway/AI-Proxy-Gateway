//! Unified application state shared across admin API, reverse proxy, and forward path.
//! Consolidates the 10+ independent Arcs that were threaded through every function.

use std::sync::Arc;

use tokio_rustls::TlsConnector;

use crate::audit::AuditChannel;
use crate::auth::Auth;
use crate::config::Config;
use crate::rbac::Rbac;
use crate::semantic::SemanticChecker;
use crate::token::TokenManager;
use crate::user_store::UserStore;
use crate::vault::Vault;

pub struct AppState {
    pub config: Arc<Config>,
    pub store: Option<Arc<UserStore>>,
    pub tokens: Option<Arc<TokenManager>>,
    pub rbac: Option<Arc<Rbac>>,
    pub auth: Option<Arc<Auth>>,
    pub vault: Vault,
    pub audit: Option<AuditChannel>,
    pub semantic: Option<Arc<SemanticChecker>>,
    pub tls_connector: TlsConnector,
    pub shutdown: Arc<std::sync::atomic::AtomicBool>,
}

impl Clone for AppState {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            store: self.store.clone(),
            tokens: self.tokens.clone(),
            rbac: self.rbac.clone(),
            auth: self.auth.clone(),
            vault: self.vault.clone(),
            audit: self.audit.clone(),
            semantic: self.semantic.clone(),
            tls_connector: self.tls_connector.clone(),
            shutdown: self.shutdown.clone(),
        }
    }
}
