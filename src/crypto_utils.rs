//! Set of cryptographic functions to simplify the Hashers.

#[cfg(any(
    feature = "with_pbkdf2",
    feature = "with_argon2",
    feature = "with_scrypt"
))]
use base64::engine::Engine as _;
#[cfg(any(
    feature = "with_pbkdf2",
    feature = "with_argon2",
    feature = "with_scrypt"
))]
use base64::engine::general_purpose;

#[cfg(any(
    feature = "with_pbkdf2",
    feature = "with_argon2",
    feature = "with_legacy",
    feature = "with_scrypt"
))]
pub fn safe_eq(a: &str, b: String) -> bool {
    constant_time_eq::constant_time_eq(a.as_bytes(), b.as_bytes())
}

#[cfg(feature = "with_argon2")]
use argon2::{self, Config, Variant, Version};

#[cfg(all(feature = "with_pbkdf2", not(feature = "fpbkdf2")))]
pub fn hash_pbkdf2_sha256(password: &str, salt: &str, iterations: u32) -> String {
    let mut result = [0u8; 32];
    use core::num::NonZeroU32;
    ring::pbkdf2::derive(
        ring::pbkdf2::PBKDF2_HMAC_SHA256,
        NonZeroU32::new(iterations).unwrap(),
        salt.as_bytes(),
        password.as_bytes(),
        &mut result,
    );
    general_purpose::STANDARD.encode(result)
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
    general_purpose::STANDARD.encode(&result)
}

#[cfg(feature = "with_pbkdf2")]
#[cfg(not(feature = "fpbkdf2"))]
pub fn hash_pbkdf2_sha1(password: &str, salt: &str, iterations: u32) -> String {
    let mut result = [0u8; 20];
    use core::num::NonZeroU32;
    ring::pbkdf2::derive(
        ring::pbkdf2::PBKDF2_HMAC_SHA1,
        NonZeroU32::new(iterations).unwrap(),
        salt.as_bytes(),
        password.as_bytes(),
        &mut result,
    );
    general_purpose::STANDARD.encode(result)
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
    general_purpose::STANDARD.encode(&result)
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
        secret: &[],
        ad: &[],
        hash_length,
    };
    let salt_bytes = general_purpose::URL_SAFE_NO_PAD.decode(salt).unwrap();
    let result = argon2::hash_raw(password.as_bytes(), &salt_bytes, &config).unwrap();
    general_purpose::URL_SAFE_NO_PAD.encode(result)
}

#[cfg(feature = "with_scrypt")]
use scrypt::{Params, scrypt};

#[cfg(feature = "with_scrypt")]
pub fn hash_scrypt(
    password: &str,
    salt: &str,
    work_factor: u8,
    block_size: u32,
    parallelism: u32,
) -> String {
    const KEY_SIZE: usize = 64;
    let mut buf = [0u8; KEY_SIZE];
    let params = Params::new(work_factor, block_size, parallelism, KEY_SIZE).unwrap();
    scrypt(password.as_bytes(), salt.as_bytes(), &params, &mut buf).unwrap();
    general_purpose::STANDARD.encode(buf)
}
