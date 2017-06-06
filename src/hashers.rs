extern crate base64;
use self::base64::decode as base64_decode;

use std::str;
use crypto_utils;

/// Possible errors during a hash creation.
#[derive(PartialEq, Debug)]
pub enum HasherError {
    /// Algorithm not recognizable.
    UnknownAlgorithm,
    /// Number of iterations is not a positive integer.
    EmptyHash,
    /// Hash string is empty.
    InvalidIterations,
    /// Argon2 salt should be Base64 encoded.
    InvalidArgon2Salt,
}

/// Hasher abstraction, providing methods to encode and verify hashes.
pub trait Hasher {
    /// Verifies a password against an encoded hash.
    fn verify(&self, password: &str, encoded: &str) -> Result<bool, HasherError>;
    /// Generates an encoded hash for a given password and salt.
    fn encode(&self, password: &str, salt: &str, iterations: u32) -> String;
}

// List of Hashers:

/// Hasher that uses the PBKDF2 key-derivation function with the SHA256 hashing algorithm.
pub struct PBKDF2Hasher;

impl Hasher for PBKDF2Hasher {
    fn verify(&self, password: &str, encoded: &str) -> Result<bool, HasherError> {
        let encoded_part: Vec<&str> = encoded.split("$").collect();
        let salt = encoded_part[2];
        let hash = encoded_part[3];
        let iterations: u32;
        match encoded_part[1].parse::<u32>() {
            Ok(n) => {
                iterations = n;
            }
            Err(_) => {
                return Err(HasherError::InvalidIterations);
            }
        }
        Ok(hash == crypto_utils::hash_pbkdf2_sha256(password, salt, iterations))
    }

    fn encode(&self, password: &str, salt: &str, iterations: u32) -> String {
        let hash = crypto_utils::hash_pbkdf2_sha256(password, salt, iterations);
        format!("{}${}${}${}", "pbkdf2_sha256", iterations, salt, hash)
    }
}

/// Hasher that uses the PBKDF2 key-derivation function with the SHA1 hashing algorithm.
pub struct PBKDF2SHA1Hasher;

impl Hasher for PBKDF2SHA1Hasher {
    fn verify(&self, password: &str, encoded: &str) -> Result<bool, HasherError> {
        let encoded_part: Vec<&str> = encoded.split("$").collect();
        let salt = encoded_part[2];
        let hash = encoded_part[3];
        let iterations: u32;
        match encoded_part[1].parse::<u32>() {
            Ok(n) => {
                iterations = n;
            }
            Err(_) => {
                return Err(HasherError::InvalidIterations);
            }
        }
        Ok(hash == crypto_utils::hash_pbkdf2_sha1(password, salt, iterations))
    }

    fn encode(&self, password: &str, salt: &str, iterations: u32) -> String {
        let hash = crypto_utils::hash_pbkdf2_sha1(password, salt, iterations);
        format!("{}${}${}${}", "pbkdf2_sha1", iterations, salt, hash)
    }
}

/// Hasher that uses the Argon2 function (new in Django 1.10).
pub struct Argon2Hasher;

const OLD_ARGON2_VERSION: u32 = 0x10;
const NEW_ARGON2_VERSION: u32 = 0x13;

impl Hasher for Argon2Hasher {
    fn verify(&self, password: &str, encoded: &str) -> Result<bool, HasherError> {
        let encoded_part: Vec<&str> = encoded.split("$").collect();
        let segment_shift = 6 - encoded_part.len();
        let settings = encoded_part[3 - segment_shift];
        let salt = encoded_part[4 - segment_shift];
        let hash = encoded_part[5 - segment_shift];
        let version = match segment_shift {
            0 => NEW_ARGON2_VERSION,
            _ => OLD_ARGON2_VERSION,
        };
        let settings_part: Vec<&str> = settings.split(",").collect();
        let memory_cost: u32 = settings_part[0].split("=").collect::<Vec<&str>>()[1].parse::<u32>().unwrap();
        let time_cost: u32 = settings_part[1].split("=").collect::<Vec<&str>>()[1].parse::<u32>().unwrap();
        let parallelism: u32 = settings_part[2].split("=").collect::<Vec<&str>>()[1].parse::<u32>().unwrap();

        // Django's implementation expects a Base64-encoded salt, if it is not, return an error:
        match base64_decode(salt) {
            Ok(_) => {},
            Err(_) => return Err(HasherError::InvalidArgon2Salt)
        };

        // Argon2 has a flexible hash length:
        let hash_length = match base64_decode(hash) {
            Ok(value) => value.len() as u32,
            Err(_) => return Ok(false)
        };

        Ok(hash == crypto_utils::hash_argon2(password, salt, time_cost, memory_cost, parallelism, version, hash_length))
    }

    fn encode(&self, password: &str, salt: &str, _: u32) -> String {
        // "Profile 1": Settings used in Django 1.10: This may change in the
        // future, if so, use the "iterations" parameter as a profile input,
        // and match against it:
        let memory_cost: u32 = 512;  // "kib" in Argon2's lingo.
        let time_cost: u32 = 2;  // "passes" in Argon2's lingo.
        let parallelism: u32 = 2;  // "lanes" in Argon2's lingo.
        let version: u32 = NEW_ARGON2_VERSION;
        let hash_length: u32 = 16;
        let hash = crypto_utils::hash_argon2(password, salt, time_cost, memory_cost, parallelism, version, hash_length);
        format!("argon2$argon2i$v=19$m={},t={},p={}${}${}", memory_cost, time_cost, parallelism, salt, hash)
    }

}

/// Hasher that uses the bcrypt key-derivation function with the password padded with SHA256.
pub struct BCryptSHA256Hasher;

impl Hasher for BCryptSHA256Hasher {
    fn verify(&self, password: &str, encoded: &str) -> Result<bool, HasherError> {
        let bcrypt_encoded_part: Vec<&str> = encoded.splitn(2, "$").collect();
        let hash = bcrypt_encoded_part[1];
        let hashed_password = crypto_utils::hash_sha256(password);
        match crypto_utils::verify_bcrypt(&hashed_password, hash) {
            Ok(valid) => {
                return Ok(valid);
            }
            Err(_) => {
                return Ok(false);
            }
        }
    }

    fn encode(&self, password: &str, _: &str, iterations: u32) -> String {
        let hashed_password = crypto_utils::hash_sha256(password);
        let hash = crypto_utils::hash_bcrypt(&hashed_password, iterations).unwrap();
        format!("{}${}", "bcrypt_sha256", hash)
    }
}

/// Hasher that uses the bcrypt key-derivation function without password padding.
pub struct BCryptHasher;

impl Hasher for BCryptHasher {
    fn verify(&self, password: &str, encoded: &str) -> Result<bool, HasherError> {
        let bcrypt_encoded_part: Vec<&str> = encoded.splitn(2, "$").collect();
        let hash = bcrypt_encoded_part[1];
        match crypto_utils::verify_bcrypt(password, hash) {
            Ok(valid) => {
                return Ok(valid);
            }
            Err(_) => {
                return Ok(false);
            }
        }
    }

    fn encode(&self, password: &str, _: &str, iterations: u32) -> String {
        let hash = crypto_utils::hash_bcrypt(password, iterations).unwrap();
        format!("{}${}", "bcrypt", hash)
    }
}

/// Hasher that uses the SHA1 hashing function over the salted password.
pub struct SHA1Hasher;

impl Hasher for SHA1Hasher {
    fn verify(&self, password: &str, encoded: &str) -> Result<bool, HasherError> {
        let encoded_part: Vec<&str> = encoded.split("$").collect();
        let salt = encoded_part[1];
        let hash = encoded_part[2];
        Ok(hash == crypto_utils::hash_sha1(password, salt))
    }

    fn encode(&self, password: &str, salt: &str, _: u32) -> String {
        let hash = crypto_utils::hash_sha1(password, salt);
        format!("{}${}${}", "sha1", salt, hash)
    }
}

/// Hasher that uses the MD5 hashing function over the salted password.
pub struct MD5Hasher;

impl Hasher for MD5Hasher {
    fn verify(&self, password: &str, encoded: &str) -> Result<bool, HasherError> {
        let encoded_part: Vec<&str> = encoded.split("$").collect();
        let salt = encoded_part[1];
        let hash = encoded_part[2];
        Ok(hash == crypto_utils::hash_md5(password, salt))
    }

    fn encode(&self, password: &str, salt: &str, _: u32) -> String {
        let hash = crypto_utils::hash_md5(password, salt);
        format!("{}${}${}", "md5", salt, hash)
    }
}

/// Hasher that uses the SHA1 hashing function with no salting.
pub struct UnsaltedSHA1Hasher;

impl Hasher for UnsaltedSHA1Hasher {
    fn verify(&self, password: &str, encoded: &str) -> Result<bool, HasherError> {
        let encoded_part: Vec<&str> = encoded.split("$").collect();
        let hash = encoded_part[2];
        Ok(hash == crypto_utils::hash_sha1(password, ""))
    }

    fn encode(&self, password: &str, _: &str, _: u32) -> String {
        let hash = crypto_utils::hash_sha1(password, "");
        format!("{}$${}", "sha1", hash)
    }
}

/// Hasher that uses the MD5 hashing function with no salting.
pub struct UnsaltedMD5Hasher;

impl Hasher for UnsaltedMD5Hasher {
    fn verify(&self, password: &str, encoded: &str) -> Result<bool, HasherError> {
        Ok(encoded == crypto_utils::hash_md5(password, ""))
    }

    fn encode(&self, password: &str, _: &str, _: u32) -> String {
        crypto_utils::hash_md5(password, "").to_string()
    }
}

/// Hasher that uses the UNIX's crypt(3) hash function.
pub struct CryptHasher;

impl Hasher for CryptHasher {
    fn verify(&self, password: &str, encoded: &str) -> Result<bool, HasherError> {
        let encoded_part: Vec<&str> = encoded.split("$").collect();
        let hash = encoded_part[2];
        Ok(hash == crypto_utils::hash_unix_crypt(password, hash))
    }

    fn encode(&self, password: &str, salt: &str, _: u32) -> String {
        let hash = crypto_utils::hash_unix_crypt(password, salt);
        format!("{}$${}", "crypt", hash)
    }
}
