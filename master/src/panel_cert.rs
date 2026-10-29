//! A Let's Encrypt certificate for the panel itself, so admins no longer
//! click through a browser warning (which any on-path attacker can exploit).
//!
//! The certificate is issued for the master's existing key. Nodes pin that
//! key (install commands give its hash, and the master pushes it in every
//! config as master_spki), so moving from the self-signed certificate to a
//! CA one does not cut them off. Nodes too old to understand master_spki
//! still pin the self-signed certificate itself: issuance waits until every
//! node has confirmed it accepts the key.

use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use instant_acme::{Account, AccountCredentials, AuthorizationStatus, ChallengeType, Identifier, LetsEncrypt, NewAccount, NewOrder, OrderStatus, RetryPolicy};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use serde::Serialize;

use crate::app::App;
use crate::db;
use crate::period::now;

/// Serves whichever certificate is current; renewal swaps it in place.
#[derive(Debug)]
pub struct Resolver(RwLock<Arc<CertifiedKey>>);

impl Resolver {
    pub fn new(key: Arc<CertifiedKey>) -> Self {
        Resolver(RwLock::new(key))
    }
    fn set(&self, key: Arc<CertifiedKey>) {
        *self.0.write().unwrap_or_else(|e| e.into_inner()) = key;
    }
}

impl ResolvesServerCert for Resolver {
    fn resolve(&self, _: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.0.read().unwrap_or_else(|e| e.into_inner()).clone())
    }
}

/// The master's own TLS when it uses its generated key (not -cert/-no-tls).
pub struct PanelTls {
    pub resolver: Arc<Resolver>,
    pub dir: PathBuf,
    pub key_pem: String,
}

pub fn certified(cert_pem: &[u8], key_pem: &[u8]) -> Result<Arc<CertifiedKey>, String> {
    let certs: Vec<_> = rustls_pemfile::certs(&mut &cert_pem[..]).collect::<Result<_, _>>().map_err(|e| e.to_string())?;
    if certs.is_empty() {
        return Err("no certificate".into());
    }
    let key = rustls_pemfile::private_key(&mut &key_pem[..]).map_err(|e| e.to_string())?.ok_or("no private key")?;
    let signer = rustls::crypto::ring::sign::any_supported_type(&key).map_err(|e| e.to_string())?;
    Ok(Arc::new(CertifiedKey::new(certs, signer)))
}

#[derive(Clone, Default, Serialize)]
pub struct Status {
    pub domain: String,
    /// Unix time the CA certificate expires; 0 while self-signed.
    pub not_after: i64,
    pub error: String,
}

static STATUS: Mutex<Option<Status>> = Mutex::new(None);
static KICK: std::sync::OnceLock<Arc<tokio::sync::Notify>> = std::sync::OnceLock::new();

/// Re-checks the certificate now, e.g. after the settings changed.
pub fn kick() {
    if let Some(k) = KICK.get() {
        k.notify_one();
    }
}

pub fn status() -> Option<Status> {
    STATUS.lock().unwrap_or_else(|e| e.into_inner()).clone()
}

fn set_status(s: Option<Status>) {
    *STATUS.lock().unwrap_or_else(|e| e.into_inner()) = s;
}

/// Renew this long before expiry.
const RENEW_BEFORE: i64 = 30 * 86_400;

/// Checks the certificate now and then twice a day; `kick` wakes it early
/// (after the settings change).
pub fn spawn(app: Arc<App>) {
    let wake = KICK.get_or_init(|| Arc::new(tokio::sync::Notify::new())).clone();
    tokio::spawn(async move {
        let mut retry = Duration::from_secs(300);
        loop {
            let wait = match run(&app).await {
                Ok(()) => {
                    retry = Duration::from_secs(300);
                    Duration::from_secs(12 * 3600)
                }
                Err(e) => {
                    eprintln!("panel certificate: {e}");
                    let w = retry;
                    retry = (retry * 2).min(Duration::from_secs(6 * 3600));
                    w
                }
            };
            tokio::select! {
                _ = tokio::time::sleep(wait) => {}
                _ = wake.notified() => {}
            }
        }
    });
}

/// The domain to certify: panel_url's host when it is a name.
fn domain(app: &App) -> Option<String> {
    let url = db::get_setting(&app.db(), "panel_url").ok().flatten()?;
    let rest = url.strip_prefix("https://")?;
    let host = rest.split(['/', ':']).next()?.to_ascii_lowercase();
    let ok = host.contains('.') && host.parse::<std::net::IpAddr>().is_err() && host.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-');
    ok.then_some(host)
}

async fn run(app: &Arc<App>) -> Result<(), String> {
    let Some(tls) = &app.panel_tls else { return Ok(()) };
    let enabled = db::get_setting(&app.db(), "panel_acme").ok().flatten().is_some_and(|v| v == "1");
    if !enabled {
        set_status(None);
        return Ok(());
    }
    let Some(domain) = domain(app) else {
        let e = "面板地址要填 https:// 加域名（不能是 IP）才能申请证书".to_string();
        set_status(Some(Status { error: e.clone(), ..Default::default() }));
        return Err(e);
    };
    let cert_path = tls.dir.join("acme-cert.pem");
    // A stored certificate for this name that is not due yet is just used.
    if let Ok(pem) = std::fs::read(&cert_path) {
        if let Some(not_after) = leaf_not_after(&pem, &domain) {
            if not_after - now() > RENEW_BEFORE {
                tls.resolver.set(certified(&pem, tls.key_pem.as_bytes())?);
                set_status(Some(Status { domain, not_after, error: String::new() }));
                return Ok(());
            }
        }
    }
    let waiting = nodes_not_ready(app);
    if !waiting.is_empty() {
        let e = format!("这些节点还不认主控公钥，先在它们上面运行 agent update：{}", waiting.join("、"));
        set_status(Some(Status { domain, error: e.clone(), ..Default::default() }));
        return Err(e);
    }
    match issue(app, tls, &domain).await {
        Ok(pem) => {
            let not_after = leaf_not_after(pem.as_bytes(), &domain).ok_or("CA 返回的证书不对")?;
            tls.resolver.set(certified(pem.as_bytes(), tls.key_pem.as_bytes())?);
            std::fs::write(&cert_path, &pem).map_err(|e| e.to_string())?;
            eprintln!("panel certificate for {domain} issued");
            set_status(Some(Status { domain, not_after, error: String::new() }));
            Ok(())
        }
        Err(e) => {
            set_status(Some(Status { domain, error: e.clone(), ..Default::default() }));
            Err(e)
        }
    }
}

/// Nodes that have not confirmed they accept the master's key (see the
/// spki_ready column, set when a node with "spki_pin" applies a config).
fn nodes_not_ready(app: &App) -> Vec<String> {
    let conn = app.db();
    let Ok(mut st) = conn.prepare("SELECT name, code FROM nodes WHERE spki_ready=0") else { return vec!["?".into()] };
    st.query_map([], |r| Ok(if r.get::<_, String>(0)?.is_empty() { r.get(1)? } else { r.get(0)? }))
        .map(|rows| rows.flatten().collect())
        .unwrap_or_default()
}

/// The expiry of a PEM chain's leaf, if it is valid now and names domain.
fn leaf_not_after(pem: &[u8], domain: &str) -> Option<i64> {
    let der = rustls_pemfile::certs(&mut &pem[..]).next()?.ok()?;
    // Our own file, written after the CA issued it for this CSR: checking
    // that it carries the name is enough to notice a changed panel address.
    if !der.windows(domain.len()).any(|w| w.eq_ignore_ascii_case(domain.as_bytes())) {
        return None;
    }
    let not_after = x509_not_after(der.as_ref())?;
    (not_after > now()).then_some(not_after)
}

/// notAfter of a DER certificate, read from its validity field.
fn x509_not_after(der: &[u8]) -> Option<i64> {
    // tbsCertificate: [version] serial sigAlg issuer validity ...; find the
    // second UTCTime/GeneralizedTime after the issuer by scanning for the
    // time tags in order (the first is notBefore).
    let mut times = Vec::new();
    let mut i = 0;
    while i + 2 < der.len() && times.len() < 2 {
        let (tag, len) = (der[i], der[i + 1] as usize);
        if (tag == 0x17 && len == 13) || (tag == 0x18 && len == 15) {
            if let Ok(s) = std::str::from_utf8(&der[i + 2..i + 2 + len]) {
                if s.ends_with('Z') && s[..len - 1].bytes().all(|b| b.is_ascii_digit()) {
                    times.push((tag, s.to_string()));
                    i += 2 + len;
                    continue;
                }
            }
        }
        i += 1;
    }
    let (tag, s) = times.get(1)?;
    let (year, rest) = if *tag == 0x17 {
        let y: i64 = s[..2].parse().ok()?;
        (if y < 50 { 2000 + y } else { 1900 + y }, &s[2..])
    } else {
        (s[..4].parse().ok()?, &s[4..])
    };
    let n = |a: usize| rest.get(a..a + 2).and_then(|v| v.parse::<i64>().ok());
    let (mo, d, h, mi, se) = (n(0)?, n(2)?, n(4)?, n(6)?, n(8)?);
    // days from civil (Howard Hinnant)
    let y = if mo <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (if mo > 2 { mo - 3 } else { mo + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Some(days * 86_400 + h * 3600 + mi * 60 + se)
}

async fn account(app: &App, tls: &PanelTls) -> Result<Account, String> {
    let path = tls.dir.join("acme-account.json");
    if let Ok(content) = std::fs::read(&path) {
        if let Ok(creds) = serde_json::from_slice::<AccountCredentials>(&content) {
            return Account::builder().map_err(|e| e.to_string())?.from_credentials(creds).await.map_err(|e| e.to_string());
        }
    }
    let email = db::get_setting(&app.db(), "acme_email").ok().flatten().unwrap_or_default();
    let contact = format!("mailto:{email}");
    let contacts: Vec<&str> = if email.is_empty() { vec![] } else { vec![contact.as_str()] };
    let (account, creds) = Account::builder()
        .map_err(|e| e.to_string())?
        .create(&NewAccount { contact: &contacts, terms_of_service_agreed: true, only_return_existing: false }, LetsEncrypt::Production.url().to_owned(), None)
        .await
        .map_err(|e| e.to_string())?;
    let json = serde_json::to_vec(&creds).map_err(|e| e.to_string())?;
    crate::write_private(&path, &json)?;
    Ok(account)
}

/// Runs one ACME order for domain with the master's key: DNS-01 through
/// Cloudflare when a token is set, else HTTP-01 on port 80.
async fn issue(app: &App, tls: &PanelTls, domain: &str) -> Result<String, String> {
    let account = account(app, tls).await?;
    let ids = [Identifier::Dns(domain.to_string())];
    let mut order = account.new_order(&NewOrder::new(&ids)).await.map_err(|e| e.to_string())?;
    let cf_token = db::get_setting(&app.db(), "cf_token").ok().flatten().unwrap_or_default();
    let mut cleanup_dns = Vec::new();
    let mut http: Option<tokio::task::JoinHandle<()>> = None;
    let result = async {
        let mut authzs = order.authorizations();
        while let Some(authz) = authzs.next().await {
            let mut authz = authz.map_err(|e| e.to_string())?;
            if authz.status == AuthorizationStatus::Valid {
                continue;
            }
            if !cf_token.is_empty() {
                let mut ch = authz.challenge(ChallengeType::Dns01).ok_or("CA 没有给 DNS 验证")?;
                let value = ch.key_authorization().dns_value();
                let rec = crate::dns::set_txt(&cf_token, &format!("_acme-challenge.{domain}"), &value).await?;
                cleanup_dns.push(rec);
                tokio::time::sleep(Duration::from_secs(20)).await; // let the record propagate
                ch.set_ready().await.map_err(|e| e.to_string())?;
            } else {
                let mut ch = authz.challenge(ChallengeType::Http01).ok_or("CA 没有给 HTTP 验证")?;
                let path = format!("/.well-known/acme-challenge/{}", ch.token);
                let body = ch.key_authorization().as_str().to_string();
                http = Some(serve_http01(path, body).await?);
                ch.set_ready().await.map_err(|e| e.to_string())?;
            }
        }
        let status = order.poll_ready(&RetryPolicy::default()).await.map_err(|e| e.to_string())?;
        if status != OrderStatus::Ready {
            return Err(format!("验证没通过（{status:?}）"));
        }
        let key = rcgen::KeyPair::from_pem(&tls.key_pem).map_err(|e| e.to_string())?;
        // rcgen's default subject ("rcgen self signed cert") is not a name a
        // CA accepts: the request carries only the domain.
        let mut params = rcgen::CertificateParams::new(vec![domain.to_string()]).map_err(|e| e.to_string())?;
        params.distinguished_name = rcgen::DistinguishedName::new();
        params.distinguished_name.push(rcgen::DnType::CommonName, domain);
        let csr = params.serialize_request(&key).map_err(|e| e.to_string())?;
        order.finalize_csr(csr.der()).await.map_err(|e| e.to_string())?;
        order.poll_certificate(&RetryPolicy::default()).await.map_err(|e| e.to_string())
    }
    .await;
    if let Some(h) = http {
        h.abort();
    }
    for (zone, id) in cleanup_dns {
        let _ = crate::dns::delete_record(&cf_token, &zone, &id).await;
    }
    result
}

/// Answers the one HTTP-01 request path on port 80 until aborted.
async fn serve_http01(path: String, body: String) -> Result<tokio::task::JoinHandle<()>, String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("[::]:80")
        .await
        .or(tokio::net::TcpListener::bind("0.0.0.0:80").await)
        .map_err(|e| format!("HTTP 验证要用 80 端口：{e}"))?;
    Ok(tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = listener.accept().await else { continue };
            let (path, body) = (path.clone(), body.clone());
            tokio::spawn(async move {
                let mut buf = [0u8; 2048];
                let n = match tokio::time::timeout(Duration::from_secs(5), s.read(&mut buf)).await {
                    Ok(Ok(n)) => n,
                    _ => return,
                };
                let line = String::from_utf8_lossy(&buf[..n]);
                let wanted = line.lines().next().and_then(|l| l.split(' ').nth(1)) == Some(path.as_str());
                let resp = if wanted {
                    format!("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len())
                } else {
                    "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_string()
                };
                let _ = s.write_all(resp.as_bytes()).await;
            });
        }
    }))
}
