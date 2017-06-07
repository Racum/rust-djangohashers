//! Set of cryptographic functions to simplify the Hashers.

extern crate base64;
extern crate crypto;
extern crate bcrypt;
extern crate pwhash;
extern crate cargon;

#[cfg(fpbkdf2)]
extern crate fastpbkdf2;

use std::ptr;
use self::base64::{encode_config, decode, STANDARD, URL_SAFE_NO_PAD};
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
    encode_config(&result, STANDARD)
}

#[cfg(fpbkdf2)]
pub fn hash_pbkdf2_sha256(password: &str, salt: &str, iterations: u32) -> String {
    let mut result = [0u8; 32];
    pbkdf2_hmac_sha256(&password.as_bytes(), &salt.as_bytes(), iterations, &mut result);
    encode_config(&result, STANDARD)
}

#[cfg(not(fpbkdf2))]
pub fn hash_pbkdf2_sha1(password: &str, salt: &str, iterations: u32) -> String {
    let mut mac = Hmac::new(Sha1::new(), &password.as_bytes());
    let mut result = [0u8; 20];
    pbkdf2(&mut mac, &salt.as_bytes(), iterations, &mut result);
    encode_config(&result, STANDARD)
}

#[cfg(fpbkdf2)]
pub fn hash_pbkdf2_sha1(password: &str, salt: &str, iterations: u32) -> String {
    let mut result = [0u8; 20];
    pbkdf2_hmac_sha1(&password.as_bytes(), &salt.as_bytes(), iterations, &mut result);
    encode_config(&result, STANDARD)
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

pub fn hash_argon2(password: &str, salt: &str, time_cost: u32, memory_cost: u32, parallelism: u32, version: u32, hash_length: u32) -> String {
    let salt_bytes = decode(salt).unwrap();
    let argon2i_type: usize = 1;
    let empty_value = &[];
    let mut result = vec![0u8; hash_length as usize];
    let mut context = cargon::CargonContext {
        version: version,
        t_cost: time_cost,
        m_cost: memory_cost,
        lanes: parallelism,
        out: result.as_mut_ptr(), outlen: hash_length as u32,
        pwd: password.as_bytes().as_ptr(), pwdlen: password.as_bytes().len() as u32,
        salt: salt_bytes.as_ptr(), saltlen: salt_bytes.len() as u32,
        secret: empty_value.as_ptr(), secretlen: empty_value.len() as u32,
        ad: empty_value.as_ptr(), adlen: empty_value.len() as u32,
        threads: parallelism,
        allocate_fptr: ptr::null(),
        deallocate_fptr: ptr::null(),
        flags: cargon::ARGON2_FLAG_CLEAR_MEMORY,
    };
    unsafe {
        cargon::argon2_ctx(&mut context, argon2i_type);
    }
    encode_config(&result, URL_SAFE_NO_PAD)
}
