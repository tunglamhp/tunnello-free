//! Slug → session registry. Slug allocation is atomic against concurrent
//! registrations (DashMap entry API) and enforces the global `max_sessions`
//! cap best-effort — concurrent registrations at the cap can overshoot by a
//! bounded amount; that is acceptable for the free tier.

use std::sync::Arc;

use dashmap::DashMap;
use dashmap::mapref::entry::Entry;
use ddns_proto::TokenLimits;

use crate::session::TunnelSession;
use crate::tunnel::HttpOptions;

const MAX_ALLOC_ATTEMPTS: u32 = 16;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AllocError {
    #[error("server full: {active}/{max} sessions")]
    ServerFull { active: usize, max: usize },
    #[error("slug allocation exhausted after {attempts} attempts")]
    Exhausted { attempts: u32 },
    #[error("subdomain already in use")]
    Taken,
}

pub struct Registry {
    sessions: DashMap<String, Arc<TunnelSession>>,
    max_sessions: usize,
    /// Server-wide hard cap on concurrent streams per session (0 disables),
    /// enforced on top of the token's own `max_streams`.
    max_streams_per_session: usize,
    /// custom (case-insensitive) hostname → slug.
    custom_hosts: DashMap<String, String>,
}

impl Registry {
    pub fn new(max_sessions: usize) -> Self {
        Self::with_limits(max_sessions, 512)
    }

    /// `max_sessions` global session cap + `max_streams_per_session`
    /// server-wide stream cap (0 disables the stream cap).
    pub fn with_limits(max_sessions: usize, max_streams_per_session: usize) -> Self {
        Self {
            sessions: DashMap::new(),
            max_sessions,
            max_streams_per_session,
            custom_hosts: DashMap::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.sessions.len()
    }

    pub fn is_empty(&self) -> bool {
        self.sessions.is_empty()
    }

    pub fn max_sessions(&self) -> usize {
        self.max_sessions
    }

    /// Allocate a fresh slug + session. Fails when the global cap is reached or
    /// (practically never) the slug space is exhausted.
    #[allow(clippy::too_many_arguments)]
    pub fn allocate(
        &self,
        token_id: String,
        want_tcp: bool,
        want_http: bool,
        limits: TokenLimits,
        ws_tx: tokio::sync::mpsc::Sender<axum::extract::ws::Message>,
        kill_tx: tokio::sync::watch::Sender<Option<ddns_proto::KillReason>>,
        preferred_slug: Option<String>,
        custom_host: Option<String>,
        http_options: HttpOptions,
    ) -> Result<Arc<TunnelSession>, AllocError> {
        if self.sessions.len() >= self.max_sessions {
            return Err(AllocError::ServerFull {
                active: self.sessions.len(),
                max: self.max_sessions,
            });
        }
        // Per-token cap (default 2 sessions/token). Best-effort like the
        // global cap; the count is a snapshot. 0 = unlimited, skip the check.
        if limits.max_sessions > 0 {
            let active_for_token = self
                .sessions
                .iter()
                .filter(|s| s.token_id == token_id)
                .count();
            if active_for_token >= limits.max_sessions as usize {
                return Err(AllocError::ServerFull {
                    active: active_for_token,
                    max: limits.max_sessions as usize,
                });
            }
        }
        if let Some(slug) = preferred_slug {
            let session = TunnelSession::new(
                token_id.clone(),
                slug.clone(),
                want_tcp,
                want_http,
                limits,
                ws_tx.clone(),
                kill_tx.clone(),
                http_options.clone(),
                self.max_streams_per_session,
            );
            match self.sessions.entry(slug.clone()) {
                Entry::Vacant(e) => {
                    e.insert(session.clone());
                    crate::metrics::active_sessions().set(self.sessions.len() as i64);
                    if let Some(host) = custom_host {
                        self.custom_hosts.insert(host.to_ascii_lowercase(), slug);
                    }
                    return Ok(session);
                }
                Entry::Occupied(_) => return Err(AllocError::Taken),
            }
        }
        let mut rng = rand::rng();
        for _attempt in 0..MAX_ALLOC_ATTEMPTS {
            let slug = ddns_proto::random_slug(&mut rng);
            let session = TunnelSession::new(
                token_id.clone(),
                slug.clone(),
                want_tcp,
                want_http,
                limits,
                ws_tx.clone(),
                kill_tx.clone(),
                http_options.clone(),
                self.max_streams_per_session,
            );
            match self.sessions.entry(slug) {
                Entry::Vacant(e) => {
                    e.insert(session.clone());
                    crate::metrics::active_sessions().set(self.sessions.len() as i64);
                    if let Some(host) = &custom_host {
                        self.custom_hosts
                            .insert(host.to_ascii_lowercase(), session.slug.clone());
                    }
                    return Ok(session);
                }
                Entry::Occupied(_) => continue,
            }
        }
        Err(AllocError::Exhausted {
            attempts: MAX_ALLOC_ATTEMPTS,
        })
    }

    pub fn lookup(&self, slug: &str) -> Option<Arc<TunnelSession>> {
        self.sessions.get(slug).map(|s| s.clone())
    }

    /// Resolve a custom (case-insensitive) hostname to its session.
    pub fn custom_host(&self, host: &str) -> Option<Arc<TunnelSession>> {
        self.custom_hosts
            .get(&host.to_ascii_lowercase())
            .and_then(|slug| self.lookup(slug.value()))
    }

    pub fn remove(&self, slug: &str) -> Option<Arc<TunnelSession>> {
        let removed = self.sessions.remove(slug).map(|(_, s)| s);
        if removed.is_some() {
            self.custom_hosts.retain(|_, s| s.as_str() != slug);
            crate::metrics::active_sessions().set(self.sessions.len() as i64);
        }
        removed
    }

    /// Snapshot of all live sessions for the operator dashboard.
    pub fn list(&self) -> Vec<Arc<TunnelSession>> {
        self.sessions.iter().map(|r| r.value().clone()).collect()
    }
}
