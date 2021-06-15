//! Set of cryptographic functions to simplify the Hashers.

#[cfg(any(
    feature = "with_pbkdf2",
    feature = "with_argon2",
    feature = "with_legacy"
))]
pub fn safe_eq(a: &str, b: String) -> bool {
    constant_time_eq::constant_time_eq(a.as_bytes(), b.as_bytes())
}

#[cfg(feature = "with_argon2")]
use argon2::{self, Config, ThreadMode, Variant, Version};

#[cfg(all(feature = "with_pbkdf2", not(feature = "fpbkdf2")))]
pub fn hash_pbkdf2_sha256(password: &str, salt: &str, iterations: u32) -> String {
    let mut result = [0u8; 32];
    use core::num::NonZeroU32;
    ring::pbkdf2::derive(
        ring::pbkdf2::PBKDF2_HMAC_SHA256,
        NonZeroU32::new(iterations as u32).unwrap(),
        &salt.as_bytes(),
        password.as_bytes(),
        &mut result,
    );
    base64::encode_config(&result, base64::STANDARD)
}

#[cfg(feature = "with_pbkdf2")]
#[cfg(feature = "fpbkdf2")]
pub fn hash_pbkdf2_sha256(password: &str, salt: &str, iterations: u32) -> String {
    let mut result = [0u8; 32];
    fastpbkdf2::pbkdf2_hmac_sha256(
        &password.as_bytes(),
        &salt.as_bytes(),
        iterations,
        &mut result,
    );
    base64::encode_config(&result, base64::STANDARD)
}

#[cfg(feature = "with_pbkdf2")]
#[cfg(not(feature = "fpbkdf2"))]
pub fn hash_pbkdf2_sha1(password: &str, salt: &str, iterations: u32) -> String {
    let mut result = [0u8; 20];
    use core::num::NonZeroU32;
    ring::pbkdf2::derive(
        ring::pbkdf2::PBKDF2_HMAC_SHA1,
        NonZeroU32::new(iterations as u32).unwrap(),
        &salt.as_bytes(),
        password.as_bytes(),
        &mut result,
    );
    base64::encode_config(&result, base64::STANDARD)
}

#[cfg(feature = "with_pbkdf2")]
#[cfg(feature = "fpbkdf2")]
pub fn hash_pbkdf2_sha1(password: &str, salt: &str, iterations: u32) -> String {
    let mut result = [0u8; 20];
    fastpbkdf2::pbkdf2_hmac_sha1(
        &password.as_bytes(),
        &salt.as_bytes(),
        iterations,
        &mut result,
    );
    base64::encode_config(&result, base64::STANDARD)
}

#[cfg(feature = "with_legacy")]
pub fn hash_sha1(password: &str, salt: &str) -> String {
    use hex_fmt::HexFmt;
    use sha1::{Digest, Sha1};
    let mut hasher = Sha1::new();
    hasher.update(salt);
    hasher.update(password);
    let result = hasher.finalize();
    format!("{}", HexFmt(&result[..]))
}

#[cfg(feature = "with_bcrypt")]
pub fn hash_sha256(password: &str) -> String {
    use sha2::{Digest, Sha256};
    format!("{:x}", Sha256::digest(password.as_bytes()))
}

#[cfg(feature = "with_legacy")]
pub fn hash_md5(password: &str, salt: &str) -> String {
    use hex_fmt::HexFmt;
    use md5::{Digest, Md5};
    let mut hasher = Md5::new();
    hasher.update(salt);
    hasher.update(password);
    let result = hasher.finalize();
    format!("{}", HexFmt(&result[..]))
}

#[cfg(feature = "with_legacy")]
pub fn hash_unix_crypt(password: &str, salt: &str) -> String {
    #[allow(deprecated)]
    pwhash::unix_crypt::hash_with(salt, password).unwrap_or_default()
}

#[cfg(feature = "with_argon2")]
pub fn hash_argon2(
    password: &str,
    salt: &str,
    time_cost: u32,
    memory_cost: u32,
    parallelism: u32,
    version: Version,
    hash_length: u32,
) -> String {
    let config = Config {
        variant: Variant::Argon2i,
        version,
        mem_cost: memory_cost,
        time_cost,
        lanes: parallelism,
        thread_mode: ThreadMode::Parallel,
        secret: &[],
        ad: &[],
        hash_length,
    };
    let salt_bytes = base64::decode(salt).unwrap();
    let result = argon2::hash_raw(password.as_bytes(), &salt_bytes, &config).unwrap();
    base64::encode_config(&result, base64::URL_SAFE_NO_PAD)
}
