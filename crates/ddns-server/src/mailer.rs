//! SMTP mailer for account verification + password-reset emails (spec §5).
//!
//! Env: DDNS_SMTP_HOST, DDNS_SMTP_PORT (default 587), DDNS_SMTP_USER,
//! DDNS_SMTP_PASS, DDNS_SMTP_FROM, DDNS_SMTP_TLS (starttls|tls|none).
//! When SMTP is not configured, `--dev` mode logs the link instead.

use lettre::message::Mailbox;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsMode {
    StartTls,
    Tls,
    None,
}

#[derive(Debug, Clone)]
pub struct Mailer {
    host: String,
    port: u16,
    user: String,
    pass: String,
    from: Mailbox,
    tls: TlsMode,
}

impl Mailer {
    /// Build from env. Returns `None` when `DDNS_SMTP_HOST` is unset.
    pub fn from_env() -> Option<Self> {
        let host = std::env::var("DDNS_SMTP_HOST").ok()?;
        let port = std::env::var("DDNS_SMTP_PORT")
            .ok()
            .and_then(|p| p.parse().ok())
            .unwrap_or(587);
        let user = std::env::var("DDNS_SMTP_USER").unwrap_or_default();
        let pass = std::env::var("DDNS_SMTP_PASS").unwrap_or_default();
        let from = std::env::var("DDNS_SMTP_FROM")
            .unwrap_or_else(|_| "Tunello <no-reply@localhost>".into())
            .parse::<Mailbox>()
            .ok()?;
        let tls = match std::env::var("DDNS_SMTP_TLS").as_deref() {
            Ok("tls") => TlsMode::Tls,
            Ok("none") => TlsMode::None,
            _ => TlsMode::StartTls,
        };
        Some(Self {
            host,
            port,
            user,
            pass,
            from,
            tls,
        })
    }

    pub fn from(&self) -> &Mailbox {
        &self.from
    }

    pub async fn send(&self, to: &str, subject: &str, body: &str) -> Result<(), String> {
        let msg = Message::builder()
            .from(self.from.clone())
            .to(to.parse::<Mailbox>().map_err(|e| e.to_string())?)
            .subject(subject)
            .body(body.to_string())
            .map_err(|e| e.to_string())?;
        let creds = Credentials::new(self.user.clone(), self.pass.clone());
        let transport = match self.tls {
            TlsMode::StartTls => AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&self.host)
                .map_err(|e| e.to_string())?
                .port(self.port)
                .credentials(creds)
                .build(),
            TlsMode::Tls => AsyncSmtpTransport::<Tokio1Executor>::relay(&self.host)
                .map_err(|e| e.to_string())?
                .port(self.port)
                .credentials(creds)
                .build(),
            TlsMode::None => AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&self.host)
                .port(self.port)
                .credentials(creds)
                .build(),
        };
        transport.send(msg).await.map_err(|e| e.to_string())?;
        Ok(())
    }
}

/// Deliver one email. Real SMTP when configured; otherwise `--dev` logs the
/// link (so local development needs no SMTP); otherwise an error.
pub async fn deliver(
    mailer: &Option<Mailer>,
    dev: bool,
    to: &str,
    subject: &str,
    body: &str,
    link: &str,
) -> Result<(), String> {
    match mailer {
        Some(m) => m.send(to, subject, body).await,
        None if dev => {
            tracing::info!("[dev-mail] to={to} subject={subject:?} link={link}");
            Ok(())
        }
        None => Err("SMTP not configured (set DDNS_SMTP_* or run with --dev)".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_missing_returns_none() {
        // The test binary inherits the runner env; DDNS_SMTP_HOST is not set
        // in CI/local runs unless the developer exported it.
        if std::env::var("DDNS_SMTP_HOST").is_err() {
            assert!(Mailer::from_env().is_none());
        }
    }

    #[test]
    fn tls_mode_parsing() {
        // Rust 2024: env mutation is unsafe (documented UB if racing threads).
        unsafe {
            std::env::remove_var("DDNS_SMTP_HOST");
            std::env::set_var("DDNS_SMTP_HOST", "smtp.example.com");
        }
        let m = Mailer::from_env().expect("host set");
        assert_eq!(m.tls, TlsMode::StartTls); // default
        unsafe { std::env::set_var("DDNS_SMTP_TLS", "none") };
        let m = Mailer::from_env().expect("host set");
        assert_eq!(m.tls, TlsMode::None);
        unsafe {
            std::env::remove_var("DDNS_SMTP_TLS");
            std::env::remove_var("DDNS_SMTP_HOST");
        }
    }

    #[tokio::test]
    async fn dev_deliver_logs_and_succeeds() {
        let link = "https://example.com/portal/verify?token=abc";
        assert!(
            deliver(&None, true, "x@example.com", "subj", "body", link)
                .await
                .is_ok()
        );
        assert!(
            deliver(&None, false, "x@example.com", "subj", "body", link)
                .await
                .is_err()
        );
    }
}
