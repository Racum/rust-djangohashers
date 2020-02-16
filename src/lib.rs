//! A Rust port of the password primitives used in [Django Project](https://www.djangoproject.com).
//!
//! Django's `django.contrib.auth.models.User` class has a few methods to deal with passwords,
//! like `set_password()` and `check_password()`; **DjangoHashers** implements the primitive
//! functions behind that methods. All Django's built-in hashers are supported.
//!
//! This library was conceived for Django integration, but is not limited to it; you can use
//! the password hash algorithm in any Rust project (or FFI integration), since its security
//! model is already battle-tested.

use lazy_static::lazy_static;
use rand::distributions::Alphanumeric;
use rand::Rng;
mod crypto_utils;
mod hashers;
use regex::Regex;

pub use crate::hashers::*;

/// Algorithms available to use with Hashers.
#[derive(PartialEq)]
pub enum Algorithm {
    /// PBKDF2 key-derivation function with the SHA256 hashing algorithm.
    #[cfg(feature = "with_pbkdf2")]
    PBKDF2,
    /// PBKDF2 key-derivation function with the SHA1 hashing algorithm.
    #[cfg(feature = "with_pbkdf2")]
    PBKDF2SHA1,
    /// Argon2 key-derivation function.
    #[cfg(feature = "with_argon2")]
    Argon2,
    /// Bcrypt key-derivation function with the password padded with SHA256.
    #[cfg(feature = "with_bcrypt")]
    BCryptSHA256,
    /// Bcrypt key-derivation function without password padding.
    #[cfg(feature = "with_bcrypt")]
    BCrypt,
    /// SHA1 hashing function over the salted password.
    #[cfg(feature = "with_legacy")]
    SHA1,
    /// MD5 hashing function over the salted password.
    #[cfg(feature = "with_legacy")]
    MD5,
    /// SHA1 hashing function with no salting.
    #[cfg(feature = "with_legacy")]
    UnsaltedSHA1,
    /// MD5 hashing function with no salting.
    #[cfg(feature = "with_legacy")]
    UnsaltedMD5,
    /// UNIX's crypt(3) hashing algorithm.
    #[cfg(feature = "with_legacy")]
    Crypt,
}

// Parses an encoded hash in order to detect the algorithm, returns it in an Option.
fn identify_hasher(encoded: &str) -> Option<Algorithm> {
    #[cfg(feature = "with_legacy")]
    {
        if encoded.len() == 32 && !encoded.contains('$') {
            return Some(Algorithm::UnsaltedMD5);
        }
        if encoded.len() == 46 && encoded.starts_with("sha1$$") {
            return Some(Algorithm::UnsaltedSHA1);
        }
    }

    let encoded_part: Vec<&str> = encoded.splitn(2, '$').collect();
    match encoded_part[0] {
        #[cfg(feature = "with_pbkdf2")]
        "pbkdf2_sha256" => Some(Algorithm::PBKDF2),
        #[cfg(feature = "with_pbkdf2")]
        "pbkdf2_sha1" => Some(Algorithm::PBKDF2SHA1),
        #[cfg(feature = "with_argon2")]
        "argon2" => Some(Algorithm::Argon2),
        #[cfg(feature = "with_bcrypt")]
        "bcrypt_sha256" => Some(Algorithm::BCryptSHA256),
        #[cfg(feature = "with_bcrypt")]
        "bcrypt" => Some(Algorithm::BCrypt),
        #[cfg(feature = "with_legacy")]
        "sha1" => Some(Algorithm::SHA1),
        #[cfg(feature = "with_legacy")]
        "md5" => Some(Algorithm::MD5),
        #[cfg(feature = "with_legacy")]
        "crypt" => Some(Algorithm::Crypt),
        _ => None,
    }
}

// Returns an instance of a Hasher based on the algorithm provided.
fn get_hasher(algorithm: &Algorithm) -> Box<dyn Hasher + 'static> {
    match *algorithm {
        #[cfg(feature = "with_pbkdf2")]
        Algorithm::PBKDF2 => Box::new(PBKDF2Hasher),
        #[cfg(feature = "with_pbkdf2")]
        Algorithm::PBKDF2SHA1 => Box::new(PBKDF2SHA1Hasher),
        #[cfg(feature = "with_argon2")]
        Algorithm::Argon2 => Box::new(Argon2Hasher),
        #[cfg(feature = "with_bcrypt")]
        Algorithm::BCryptSHA256 => Box::new(BCryptSHA256Hasher),
        #[cfg(feature = "with_bcrypt")]
        Algorithm::BCrypt => Box::new(BCryptHasher),
        #[cfg(feature = "with_legacy")]
        Algorithm::SHA1 => Box::new(SHA1Hasher),
        #[cfg(feature = "with_legacy")]
        Algorithm::MD5 => Box::new(MD5Hasher),
        #[cfg(feature = "with_legacy")]
        Algorithm::UnsaltedSHA1 => Box::new(UnsaltedSHA1Hasher),
        #[cfg(feature = "with_legacy")]
        Algorithm::UnsaltedMD5 => Box::new(UnsaltedMD5Hasher),
        #[cfg(feature = "with_legacy")]
        Algorithm::Crypt => Box::new(CryptHasher),
    }
}

/// Verifies if an encoded hash is properly formatted before check it cryptographically.
pub fn is_password_usable(encoded: &str) -> bool {
    match identify_hasher(encoded) {
        Some(_) => !(encoded == "" || encoded.starts_with('!')),
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
#[allow(non_camel_case_types)]
pub enum DjangoVersion {
    /// Current Django version.
    Current,
    /// Django 1.4.
    V1_4,
    /// Django 1.5.
    V1_5,
    /// Django 1.6.
    V1_6,
    /// Django 1.7.
    V1_7,
    /// Django 1.8.
    V1_8,
    /// Django 1.9.
    V1_9,
    /// Django 1.10.
    V1_10,
    /// Django 1.11.
    V1_11,
    /// Django 2.0.
    V2_0,
    /// Django 2.1.
    V2_1,
    /// Django 2.2.
    V2_2,
    /// Django 3.0.
    V3_0,
}

/// Resolves the number of iterations based on the Algorithm and the Django Version.
#[allow(unused_variables)]
fn iterations(version: &DjangoVersion, algorithm: &Algorithm) -> u32 {
    match *algorithm {
        #[cfg(feature = "with_bcrypt")]
        Algorithm::BCryptSHA256 | Algorithm::BCrypt => 12,
        #[cfg(feature = "with_pbkdf2")]
        Algorithm::PBKDF2 | Algorithm::PBKDF2SHA1 => match *version {
            DjangoVersion::V1_4 | DjangoVersion::V1_5 => 10_000,
            DjangoVersion::V1_6 | DjangoVersion::V1_7 => 12_000,
            DjangoVersion::V1_8 => 20_000,
            DjangoVersion::V1_9 => 24_000,
            DjangoVersion::V1_10 => 30_000,
            DjangoVersion::V1_11 => 36_000,
            DjangoVersion::V2_0 => 100_000,
            DjangoVersion::V2_1 => 120_000,
            DjangoVersion::V2_2 | DjangoVersion::Current => 150_000,
            DjangoVersion::V3_0 => 180_000,
        },
        #[cfg(feature = "with_argon2")]
        Algorithm::Argon2 => 1, // For Argon2, this means "Profile 1", not actually "1 integration".
        #[cfg(feature = "with_legacy")]
        Algorithm::SHA1
        | Algorithm::MD5
        | Algorithm::UnsaltedSHA1
        | Algorithm::UnsaltedMD5
        | Algorithm::Crypt => 1,
    }
}

/// Generates a random salt.
fn random_salt() -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(12)
        .collect()
}

lazy_static! {
    pub static ref VALID_SALT_RE: Regex = Regex::new(r"^[A-Za-z0-9]*$").unwrap();
}

/// Core function that generates all combinations of passwords:
pub fn make_password_core(
    password: &str,
    salt: &str,
    algorithm: Algorithm,
    version: DjangoVersion,
) -> String {
    assert!(
        VALID_SALT_RE.is_match(salt),
        "Salt can only contain letters and numbers."
    );
    let hasher = get_hasher(&algorithm);
    hasher.encode(password, salt, iterations(&version, &algorithm))
}

/// Based on the current Django version, generates an encoded hash given
/// a complete set of parameters: password, salt and algorithm.
pub fn make_password_with_settings(password: &str, salt: &str, algorithm: Algorithm) -> String {
    make_password_core(password, salt, algorithm, DjangoVersion::Current)
}

/// Based on the current Django version, generates an encoded hash given
/// a password and algorithm, uses a random salt.
pub fn make_password_with_algorithm(password: &str, algorithm: Algorithm) -> String {
    make_password_core(password, &random_salt(), algorithm, DjangoVersion::Current)
}

mod features {
    use super::Algorithm;

    #[cfg(feature = "with_pbkdf2")]
    pub const PREFERRED_ALGORITHM: Algorithm = Algorithm::PBKDF2;

    #[cfg(all(not(feature = "with_pbkdf2"), feature = "with_bcrypt"))]
    pub const PREFERRED_ALGORITHM: Algorithm = Algorithm::BCryptSHA256;

    #[cfg(all(
        not(feature = "with_pbkdf2"),
        not(feature = "with_bcrypt"),
        feature = "with_argon2"
    ))]
    pub const PREFERRED_ALGORITHM: Algorithm = Algorithm::Argon2;

    #[cfg(all(
        not(feature = "with_pbkdf2"),
        not(feature = "with_bcrypt"),
        not(feature = "with_argon2"),
        feature = "with_legacy"
    ))]
    pub const PREFERRED_ALGORITHM: Algorithm = Algorithm::SHA1;

    #[cfg(all(
        not(feature = "with_pbkdf2"),
        not(feature = "with_bcrypt"),
        not(feature = "with_argon2"),
        not(feature = "with_legacy"),
    ))]
    compile_error!(
        r#"At least one of the crypto features ("with_pbkdf2", "with_bcrypt", "with_argon2" or "with_legacy") must be selected."#
    );
}

/// Based on the current Django version, generates an encoded hash given
/// only a password, uses a random salt and the PBKDF2 algorithm.
pub fn make_password(password: &str) -> String {
    make_password_core(
        password,
        &random_salt(),
        features::PREFERRED_ALGORITHM,
        DjangoVersion::Current,
    )
}

/// Abstraction that exposes the functions that generates
/// passwords compliant with different Django versions.
///
/// # Example:
///
/// ```
/// let django = Django {version: DjangoVersion::V19};
/// let encoded = django.make_password("KRONOS");
/// ```
pub struct Django {
    /// Django Version.
    pub version: DjangoVersion,
}

impl Django {
    /// Based on the defined Django version, generates an encoded hash given
    /// a complete set of parameters: password, salt and algorithm.
    pub fn make_password_with_settings(
        &self,
        password: &str,
        salt: &str,
        algorithm: Algorithm,
    ) -> String {
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
        make_password_core(
            password,
            &random_salt(),
            features::PREFERRED_ALGORITHM,
            self.version.clone(),
        )
    }
}

#[test]
fn test_identify_hasher() {
    // Good hashes:
    #[cfg(feature = "with_pbkdf2")]
    assert!(
        identify_hasher(
            "pbkdf2_sha256$24000$KQ8zeK6wKRuR$cmhbSt1XVKuO4FGd9+AX8qSBD4Z0395nZatXTJpEtTY="
        )
        .unwrap()
            == Algorithm::PBKDF2
    );
    #[cfg(feature = "with_pbkdf2")]
    assert!(
        identify_hasher("pbkdf2_sha1$24000$KQ8zeK6wKRuR$tSJh4xdxfMJotlxfkCGjTFpGYZU=").unwrap()
            == Algorithm::PBKDF2SHA1
    );
    #[cfg(feature = "with_legacy")]
    assert!(
        identify_hasher("sha1$KQ8zeK6wKRuR$f83371bca01fa6089456e673ccfb17f42d810b00").unwrap()
            == Algorithm::SHA1
    );
    #[cfg(feature = "with_legacy")]
    assert!(
        identify_hasher("md5$KQ8zeK6wKRuR$0137e4d74cb2d9ed9cb1a5f391f6175e").unwrap()
            == Algorithm::MD5
    );
    #[cfg(feature = "with_legacy")]
    assert!(identify_hasher("7cf6409a82cd4c8b96a9ecf6ad679119").unwrap() == Algorithm::UnsaltedMD5);
    #[cfg(feature = "with_legacy")]
    assert!(identify_hasher("md5$$7cf6409a82cd4c8b96a9ecf6ad679119").unwrap() == Algorithm::MD5);
    #[cfg(feature = "with_legacy")]
    assert!(
        identify_hasher("sha1$$22e6217f026c7a395f0840c1ffbdb163072419e7").unwrap()
            == Algorithm::UnsaltedSHA1
    );
    #[cfg(feature = "with_bcrypt")]
    assert!(
        identify_hasher(
            "bcrypt_sha256$$2b$12$LZSJchsWG/DrBy1erNs4eeYo6tZNlLFQmONdxN9HPesa1EyXVcTXK"
        )
        .unwrap()
            == Algorithm::BCryptSHA256
    );
    #[cfg(feature = "with_bcrypt")]
    assert!(
        identify_hasher("bcrypt$$2b$12$LZSJchsWG/DrBy1erNs4ee31eJ7DaWiuwhDOC7aqIyqGGggfu6Y/.")
            .unwrap()
            == Algorithm::BCrypt
    );
    #[cfg(feature = "with_legacy")]
    assert!(identify_hasher("crypt$$ab1Hv2Lg7ltQo").unwrap() == Algorithm::Crypt);
    #[cfg(feature = "with_argon2")]
    assert!(
        identify_hasher(
            "argon2$argon2i$v=19$m=512,t=2,p=2$MktOZjRsaTBNWnVp$/s1VqdEUfHOPKJyIokwa2A"
        )
        .unwrap()
            == Algorithm::Argon2
    );

    // Bad hashes:
    assert!(identify_hasher("").is_none());
    assert!(identify_hasher("password").is_none());
    assert!(identify_hasher("7cf6409a82cd4c8b96a9ecf6ad6791190").is_none());
    assert!(
        identify_hasher("blah$KQ8zeK6wKRuR$f83371bca01fa6089456e673ccfb17f42d810b00").is_none()
    );
}

#[test]
#[should_panic]
#[cfg(feature = "with_pbkdf2")]
fn test_invalid_salt_should_panic() {
    let _ = make_password_core("pass", "$alt", Algorithm::PBKDF2, DjangoVersion::Current);
}
