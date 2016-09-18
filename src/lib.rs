//! A Rust port of the password primitives used in [Django Project](https://www.djangoproject.com).
//!
//! Django's `django.contrib.auth.models.User` class has a few methods to deal with passwords,
//! like `set_password()` and `check_password()`; **DjangoHashers** implements the primitive
//! functions behind that methods. All Django's built-in hashers are supported.
//!
//! This library was conceived for Django integration, but is not limited to it; you can use
//! the password hash algorithm in any Rust project (or FFI integration), since its security
//! model is already battle-tested.

extern crate rand;
extern crate regex;
#[macro_use] extern crate lazy_static;

use rand::Rng;
mod crypto_utils;
mod hashers;
use regex::Regex;

pub use hashers::*;

/// Algorithms available to use with Hashers.
#[derive(PartialEq)]
pub enum Algorithm {
    /// PBKDF2 key-derivation function with the SHA256 hashing algorithm.
    PBKDF2,
    /// PBKDF2 key-derivation function with the SHA1 hashing algorithm.
    PBKDF2SHA1,
    /// Bcrypt key-derivation function with the password padded with SHA256.
    BCryptSHA256,
    /// Bcrypt key-derivation function without password padding.
    BCrypt,
    /// SHA1 hashing function over the salted password.
    SHA1,
    /// MD5 hashing function over the salted password.
    MD5,
    /// SHA1 hashing function with no salting.
    UnsaltedSHA1,
    /// MD5 hashing function with no salting.
    UnsaltedMD5,
    /// UNIX's crypt(3) hashing algorithm.
    Crypt,
}

// Parses an encoded hash in order to detect the algorithm, returns it in an Option.
fn identify_hasher(encoded: &str) -> Option<Algorithm> {
    if encoded.len() == 32 && !encoded.contains("$") {
        Some(Algorithm::UnsaltedMD5)
    } else if encoded.len() == 46 && encoded.starts_with("sha1$$") {
        Some(Algorithm::UnsaltedSHA1)
    } else {
        let encoded_part: Vec<&str> = encoded.splitn(2, "$").collect();
        match encoded_part[0] {
            "pbkdf2_sha256" => Some(Algorithm::PBKDF2),
            "pbkdf2_sha1" => Some(Algorithm::PBKDF2SHA1),
            "bcrypt_sha256" => Some(Algorithm::BCryptSHA256),
            "bcrypt" => Some(Algorithm::BCrypt),
            "sha1" => Some(Algorithm::SHA1),
            "md5" => Some(Algorithm::MD5),
            "crypt" => Some(Algorithm::Crypt),
            _ => None,
        }
    }
}

// Returns an instance of a Hasher based on the algorithm provided.
fn get_hasher(algorithm: &Algorithm) -> Box<Hasher + 'static> {
    match algorithm {
        &Algorithm::PBKDF2 => Box::new(PBKDF2Hasher),
        &Algorithm::PBKDF2SHA1 => Box::new(PBKDF2SHA1Hasher),
        &Algorithm::BCryptSHA256 => Box::new(BCryptSHA256Hasher),
        &Algorithm::BCrypt => Box::new(BCryptHasher),
        &Algorithm::SHA1 => Box::new(SHA1Hasher),
        &Algorithm::MD5 => Box::new(MD5Hasher),
        &Algorithm::UnsaltedSHA1 => Box::new(UnsaltedSHA1Hasher),
        &Algorithm::UnsaltedMD5 => Box::new(UnsaltedMD5Hasher),
        &Algorithm::Crypt => Box::new(CryptHasher),
    }
}

/// Verifies if an encoded hash is properly formatted before check it cryptographically.
pub fn is_password_usable(encoded: &str) -> bool {
    match identify_hasher(encoded) {
        Some(_) => !(encoded == "" || encoded.starts_with("!")),
        None => false,
    }
}

/// Verifies a password against an encoded hash, returns a Result.
pub fn check_password(password: &str, encoded: &str) -> Result<bool, HasherError> {
    if encoded == "" {
        return Err(HasherError::EmptyHash);
    }
    match identify_hasher(encoded) {
        Some(algorithm) => {
            let hasher = get_hasher(&algorithm);
            hasher.verify(password, encoded)
        }
        None => Err(HasherError::UnknownAlgorithm),
    }
}

/// Verifies a password against an encoded hash, returns a boolean, even in case of error.
pub fn check_password_tolerant(password: &str, encoded: &str) -> bool {
    match check_password(password, encoded) {
        Ok(valid) => valid,
        Err(_) => false,
    }
}

/// Django Version.
#[derive(Clone)]
pub enum Version {
    /// Current Django version.
    Current,
    /// Django 1.4.
    V14,
    /// Django 1.5.
    V15,
    /// Django 1.6.
    V16,
    /// Django 1.7.
    V17,
    /// Django 1.8.
    V18,
    /// Django 1.9.
    V19,
    /// Django 1.10.
    V110,
}

/// Resolves the number of iterations based on the Algorithm and the Django Version.
fn iterations(version: &Version, algorithm: &Algorithm) -> u32 {
    match algorithm {
        &Algorithm::BCryptSHA256 | &Algorithm::BCrypt => 12,
        &Algorithm::PBKDF2 | &Algorithm::PBKDF2SHA1 => match version {
            &Version::V14 | &Version::V15 => 10000,
            &Version::V16 | &Version::V17 => 12000,
            &Version::V18 => 20000,
            &Version::V19 | &Version::Current => 24000,
            &Version::V110 => 30000,
        },
        _ => 1,
    }
}

/// Generates a random salt.
fn random_salt() -> String {
    rand::thread_rng().gen_ascii_chars().take(12).collect::<String>()
}

lazy_static! {
    pub static ref VALID_SALT_RE: Regex = Regex::new(r"^[A-Za-z0-9]*$").unwrap();
}

/// Core function that generates all combinations of passwords:
pub fn make_password_core(password: &str, salt: &str, algorithm: Algorithm, version: Version) -> String {
    assert!(VALID_SALT_RE.is_match(salt), "Salt can only contain letters and numbers.");
    let hasher = get_hasher(&algorithm);
    hasher.encode(password, salt, iterations(&version, &algorithm))
}

/// Based on the current Django version, generates an encoded hash given
/// a complete set of parameters: password, salt and algorithm.
pub fn make_password_with_settings(password: &str, salt: &str, algorithm: Algorithm) -> String {
    make_password_core(password, salt, algorithm, Version::Current)
}

/// Based on the current Django version, generates an encoded hash given
/// a password and algorithm, uses a random salt.
pub fn make_password_with_algorithm(password: &str, algorithm: Algorithm) -> String {
    make_password_core(password, &random_salt(), algorithm, Version::Current)
}

/// Based on the current Django version, generates an encoded hash given
/// only a password, uses a random salt and the PBKDF2 algorithm.
pub fn make_password(password: &str) -> String {
    make_password_core(password, &random_salt(), Algorithm::PBKDF2, Version::Current)
}

/// Abstraction that exposes the functions that generates
/// passwords compliant with different Django versions.
///
/// # Example:
///
/// ```
/// let django = Django {version: Version::V19};
/// let encoded = django.make_password("KRONOS");
/// ```
pub struct Django {
    /// Django Version.
    pub version: Version
}

impl Django {

    /// Based on the defined Django version, generates an encoded hash given
    /// a complete set of parameters: password, salt and algorithm.
    pub fn make_password_with_settings(&self, password: &str, salt: &str, algorithm: Algorithm) -> String {
        make_password_core(password, salt, algorithm, self.version.clone())
    }

    /// Based on the defined Django version, generates an encoded hash given
    /// a password and algorithm, uses a random salt.
    pub fn make_password_with_algorithm(&self, password: &str, algorithm: Algorithm) -> String {
        make_password_core(password, &random_salt(), algorithm, self.version.clone())
    }

    /// Based on the defined Django version, generates an encoded hash given
    /// only a password, uses a random salt and the PBKDF2 algorithm.
    pub fn make_password(&self, password: &str) -> String {
        make_password_core(password, &random_salt(), Algorithm::PBKDF2, self.version.clone())
    }

}

#[test]
fn test_identify_hasher() {

    // Good hashes:
    assert!(identify_hasher("pbkdf2_sha256$24000$KQ8zeK6wKRuR$cmhbSt1XVKuO4FGd9+AX8qSBD4Z0395nZatXTJpEtTY=")
                .unwrap() == Algorithm::PBKDF2);
    assert!(identify_hasher("pbkdf2_sha1$24000$KQ8zeK6wKRuR$tSJh4xdxfMJotlxfkCGjTFpGYZU=")
                .unwrap() == Algorithm::PBKDF2SHA1);
    assert!(identify_hasher("sha1$KQ8zeK6wKRuR$f83371bca01fa6089456e673ccfb17f42d810b00")
                .unwrap() == Algorithm::SHA1);
    assert!(identify_hasher("md5$KQ8zeK6wKRuR$0137e4d74cb2d9ed9cb1a5f391f6175e")
                .unwrap() == Algorithm::MD5);
    assert!(identify_hasher("7cf6409a82cd4c8b96a9ecf6ad679119")
                .unwrap() == Algorithm::UnsaltedMD5);
    assert!(identify_hasher("md5$$7cf6409a82cd4c8b96a9ecf6ad679119")
                .unwrap() == Algorithm::MD5);
    assert!(identify_hasher("sha1$$22e6217f026c7a395f0840c1ffbdb163072419e7")
                .unwrap() == Algorithm::UnsaltedSHA1);
    assert!(identify_hasher("bcrypt_sha256$$2b$12$LZSJchsWG/DrBy1erNs4eeYo6tZNlLFQmONdxN9HPesa1EyXVcTXK")
                .unwrap() == Algorithm::BCryptSHA256);
    assert!(identify_hasher("bcrypt$$2b$12$LZSJchsWG/DrBy1erNs4ee31eJ7DaWiuwhDOC7aqIyqGGggfu6Y/.")
                .unwrap() == Algorithm::BCrypt);
    assert!(identify_hasher("crypt$$ab1Hv2Lg7ltQo")
                .unwrap() == Algorithm::Crypt);

    // Bad hashes:
    assert!(identify_hasher("").is_none());
    assert!(identify_hasher("password").is_none());
    assert!(identify_hasher("7cf6409a82cd4c8b96a9ecf6ad6791190").is_none());
    assert!(identify_hasher("blah$KQ8zeK6wKRuR$f83371bca01fa6089456e673ccfb17f42d810b00").is_none());

}

#[test]
#[should_panic]
fn test_invalid_salt_should_panic() {
    let _ = make_password_core("pass", "$alt", Algorithm::PBKDF2, Version::Current);
}
