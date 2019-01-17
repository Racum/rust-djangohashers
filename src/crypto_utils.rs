//! Set of cryptographic functions to simplify the Hashers.

#[cfg(any(feature="with_pbkdf2", feature="with_argon2", feature="with_legacy"))]
pub fn safe_eq(a: &str, b: String) -> bool {
    constant_time_eq::constant_time_eq(a.as_bytes(), b.as_bytes())
}

#[cfg(all(feature="with_pbkdf2", not(feature="fpbkdf2")))]
pub fn hash_pbkdf2_sha256(password: &str, salt: &str, iterations: u32) -> String {
    use crypto::{hmac::Hmac, sha2::Sha256, pbkdf2::pbkdf2};
    let mut mac = Hmac::new(Sha256::new(), &password.as_bytes());
    let mut result = [0u8; 32];
    pbkdf2(&mut mac, &salt.as_bytes(), iterations, &mut result);
    base64::encode_config(&result, base64::STANDARD)
}

#[cfg(feature="with_pbkdf2")]
#[cfg(feature="fpbkdf2")]
pub fn hash_pbkdf2_sha256(password: &str, salt: &str, iterations: u32) -> String {
    let mut result = [0u8; 32];
    fastpbkdf2::pbkdf2_hmac_sha256(&password.as_bytes(), &salt.as_bytes(), iterations, &mut result);
    base64::encode_config(&result, base64::STANDARD)
}

#[cfg(feature="with_pbkdf2")]
#[cfg(not(feature="fpbkdf2"))]
pub fn hash_pbkdf2_sha1(password: &str, salt: &str, iterations: u32) -> String {
    use crypto::{hmac::Hmac, sha1::Sha1, pbkdf2::pbkdf2};
    let mut mac = Hmac::new(Sha1::new(), &password.as_bytes());
    let mut result = [0u8; 20];
    pbkdf2(&mut mac, &salt.as_bytes(), iterations, &mut result);
    base64::encode_config(&result, base64::STANDARD)
}

#[cfg(feature="with_pbkdf2")]
#[cfg(feature="fpbkdf2")]
pub fn hash_pbkdf2_sha1(password: &str, salt: &str, iterations: u32) -> String {
    let mut result = [0u8; 20];
    fastpbkdf2::pbkdf2_hmac_sha1(&password.as_bytes(), &salt.as_bytes(), iterations, &mut result);
    base64::encode_config(&result, base64::STANDARD)
}

#[cfg(feature="with_legacy")]
pub fn hash_sha1(password: &str, salt: &str) -> String {
    use crypto::{sha1::Sha1, digest::Digest};
    let mut sha = Sha1::new();
    sha.input_str(salt);
    sha.input_str(password);
    sha.result_str()
}

#[cfg(feature="with_bcrypt")]
pub fn hash_sha256(password: &str) -> String {
    use crypto::{sha2::Sha256, digest::Digest};
    let mut sha = Sha256::new();
    sha.input_str(password);
    sha.result_str()
}

#[cfg(feature="with_legacy")]
pub fn hash_md5(password: &str, salt: &str) -> String {
    use crypto::{md5::Md5, digest::Digest};
    let mut md5 = Md5::new();
    md5.input_str(salt);
    md5.input_str(password);
    md5.result_str()
}

#[cfg(feature="with_legacy")]
pub fn hash_unix_crypt(password: &str, salt: &str) -> String {
    #[allow(deprecated)]
    match pwhash::unix_crypt::hash_with(salt, password) {
        Ok(value) => value,
        Err(_) => "".to_string()
    }
}

#[cfg(feature="with_argon2")]
pub fn hash_argon2(password: &str, salt: &str, time_cost: u32, memory_cost: u32, parallelism: u32, version: u32, hash_length: u32) -> String {
    let salt_bytes = base64::decode(salt).unwrap();
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
        allocate_fptr: std::ptr::null(),
        deallocate_fptr: std::ptr::null(),
        flags: cargon::ARGON2_FLAG_CLEAR_MEMORY,
    };
    unsafe {
        cargon::argon2_ctx(&mut context, argon2i_type);
    }
    base64::encode_config(&result, base64::URL_SAFE_NO_PAD)
}
