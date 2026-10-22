use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use rand::RngCore;
use sha2::{Digest, Sha256};

pub fn random_bytes(n: usize) -> Vec<u8> {
    let mut b = vec![0u8; n];
    rand::thread_rng().fill_bytes(&mut b);
    b
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn random_hex(n: usize) -> String {
    hex(&random_bytes(n))
}

/// Standard base64, as SS 2022 keys are written.
pub fn random_b64(n: usize) -> String {
    STANDARD.encode(random_bytes(n))
}

pub fn random_uuid() -> String {
    let mut b = random_bytes(16);
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let h = hex(&b);
    format!("{}-{}-{}-{}-{}", &h[0..8], &h[8..12], &h[12..16], &h[16..20], &h[20..32])
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

/// A random high port for a new listener, so fresh nodes do not sit on
/// ports scanners try first. `taken` are ports already used on that node.
pub fn random_port(taken: &[i64]) -> i64 {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    loop {
        let p = rng.gen_range(20000..=59999);
        if !taken.contains(&p) && p % 1000 != 0 {
            return p;
        }
    }
}

/// Reality X25519 key pair as Xray prints it: (private, public), base64 raw URL.
pub fn reality_keypair() -> (String, String) {
    let secret = x25519_dalek::StaticSecret::random_from_rng(rand::thread_rng());
    let public = x25519_dalek::PublicKey::from(&secret);
    (URL_SAFE_NO_PAD.encode(secret.to_bytes()), URL_SAFE_NO_PAD.encode(public.as_bytes()))
}

/// The SS 2022 user key an entry uses on one exit port. Derived from the
/// master secret so nothing has to be stored per pair.
pub fn exit_key(secret: &str, entry: i64, exit: i64) -> String {
    let d = sha256(format!("keel exit key\0{secret}\0{entry}\0{exit}").as_bytes());
    STANDARD.encode(&d[..16])
}

pub fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}
