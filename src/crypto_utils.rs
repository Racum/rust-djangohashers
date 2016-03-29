//! Set of cryptographic functions to simplify the Hashers.

extern crate rustc_serialize;
extern crate crypto;
extern crate bcrypt;
extern crate pwhash;

#[cfg(fpbkdf2)]
extern crate fastpbkdf2;

use self::rustc_serialize::base64::{STANDARD, ToBase64};
use self::crypto::digest::Digest;
use self::crypto::sha2::Sha256;
use self::crypto::sha1::Sha1;
use self::crypto::md5::Md5;
use self::pwhash::unix_crypt::hash_with;

#[cfg(not(fpbkdf2))]
use self::crypto::hmac::Hmac;
#[cfg(not(fpbkdf2))]
use self::crypto::pbkdf2::pbkdf2;
#[cfg(fpbkdf2)]
use self::fastpbkdf2::{pbkdf2_hmac_sha1, pbkdf2_hmac_sha256};

pub use self::bcrypt::hash as hash_bcrypt;
pub use self::bcrypt::verify as verify_bcrypt;

#[cfg(not(fpbkdf2))]
pub fn hash_pbkdf2_sha256(password: &str, salt: &str, iterations: u32) -> String {
    let mut mac = Hmac::new(Sha256::new(), &password.as_bytes());
    let mut result = [0u8; 32];
    pbkdf2(&mut mac, &salt.as_bytes(), iterations, &mut result);
    result.to_base64(STANDARD)
}

#[cfg(fpbkdf2)]
pub fn hash_pbkdf2_sha256(password: &str, salt: &str, iterations: u32) -> String {
    let mut result = [0u8; 32];
    pbkdf2_hmac_sha256(&password.as_bytes(), &salt.as_bytes(), iterations, &mut result);
    result.to_base64(STANDARD)
}

#[cfg(not(fpbkdf2))]
pub fn hash_pbkdf2_sha1(password: &str, salt: &str, iterations: u32) -> String {
    let mut mac = Hmac::new(Sha1::new(), &password.as_bytes());
    let mut result = [0u8; 20];
    pbkdf2(&mut mac, &salt.as_bytes(), iterations, &mut result);
    result.to_base64(STANDARD)
}

#[cfg(fpbkdf2)]
pub fn hash_pbkdf2_sha1(password: &str, salt: &str, iterations: u32) -> String {
    let mut result = [0u8; 20];
    pbkdf2_hmac_sha1(&password.as_bytes(), &salt.as_bytes(), iterations, &mut result);
    result.to_base64(STANDARD)
}

pub fn hash_sha1(password: &str, salt: &str) -> String {
    let mut sha = Sha1::new();
    sha.input_str(salt);
    sha.input_str(password);
    sha.result_str()
}

pub fn hash_sha256(password: &str) -> String {
    let mut sha = Sha256::new();
    sha.input_str(password);
    sha.result_str()
}

pub fn hash_md5(password: &str, salt: &str) -> String {
    let mut md5 = Md5::new();
    md5.input_str(salt);
    md5.input_str(password);
    md5.result_str()
}

pub fn hash_unix_crypt(password: &str, salt: &str) -> String {
    match hash_with(salt, password) {
        Ok(value) => value,
        Err(_) => "".to_string()
    }
}
