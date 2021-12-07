use crate::crypto_utils;
use std::str;

#[cfg(feature = "with_pbkdf2")]
static PBKDF2_ITERATIONS_DOS_LIMIT: u32 = 1_000_000;
#[cfg(feature = "with_bcrypt")]
static BCRYPT_COST_DOS_LIMIT: u32 = 16;

/// Possible errors during a hash creation.
#[derive(PartialEq, Debug)]
pub enum HasherError {
    /// Algorithm not recognizable.
    UnknownAlgorithm,
    /// Hash string is corrupted.
    BadHash,
    /// Hash string is empty.
    EmptyHash,
    /// Number of iterations is not a positive integer.
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
#[cfg(feature = "with_pbkdf2")]
pub struct PBKDF2Hasher;

#[cfg(feature = "with_pbkdf2")]
impl Hasher for PBKDF2Hasher {
    fn verify(&self, password: &str, encoded: &str) -> Result<bool, HasherError> {
        let mut encoded_part = encoded.split('$').skip(1);
        let iterations = encoded_part
            .next()
            .ok_or(HasherError::BadHash)?
            .parse::<u32>()
            .map_err(|_| HasherError::InvalidIterations)?;
        if iterations > PBKDF2_ITERATIONS_DOS_LIMIT {
            return Err(HasherError::InvalidIterations);
        }
        let salt = encoded_part.next().ok_or(HasherError::BadHash)?;
        let hash = encoded_part.next().ok_or(HasherError::BadHash)?;
        Ok(crypto_utils::safe_eq(
            hash,
            crypto_utils::hash_pbkdf2_sha256(password, salt, iterations),
        ))
    }

    fn encode(&self, password: &str, salt: &str, iterations: u32) -> String {
        let hash = crypto_utils::hash_pbkdf2_sha256(password, salt, iterations);
        format!("{}${}${}${}", "pbkdf2_sha256", iterations, salt, hash)
    }
}

/// Hasher that uses the PBKDF2 key-derivation function with the SHA1 hashing algorithm.
#[cfg(feature = "with_pbkdf2")]
pub struct PBKDF2SHA1Hasher;

#[cfg(feature = "with_pbkdf2")]
impl Hasher for PBKDF2SHA1Hasher {
    fn verify(&self, password: &str, encoded: &str) -> Result<bool, HasherError> {
        let mut encoded_part = encoded.split('$').skip(1);
        let iterations = encoded_part
            .next()
            .ok_or(HasherError::BadHash)?
            .parse::<u32>()
            .map_err(|_| HasherError::InvalidIterations)?;
        if iterations > PBKDF2_ITERATIONS_DOS_LIMIT {
            return Err(HasherError::InvalidIterations);
        }
        let salt = encoded_part.next().ok_or(HasherError::BadHash)?;
        let hash = encoded_part.next().ok_or(HasherError::BadHash)?;
        Ok(crypto_utils::safe_eq(
            hash,
            crypto_utils::hash_pbkdf2_sha1(password, salt, iterations),
        ))
    }

    fn encode(&self, password: &str, salt: &str, iterations: u32) -> String {
        let hash = crypto_utils::hash_pbkdf2_sha1(password, salt, iterations);
        format!("{}${}${}${}", "pbkdf2_sha1", iterations, salt, hash)
    }
}

/// Hasher that uses the Argon2 function (new in Django 1.10).
#[cfg(feature = "with_argon2")]
pub struct Argon2Hasher;

#[cfg(feature = "with_argon2")]
use argon2::{self, Version};

#[cfg(feature = "with_argon2")]
impl Hasher for Argon2Hasher {
    fn verify(&self, password: &str, encoded: &str) -> Result<bool, HasherError> {
        let encoded_part: Vec<&str> = encoded.split('$').collect();
        let version = match encoded_part.len() {
            6 => Version::Version13,
            5 => Version::Version10,
            _ => return Err(HasherError::BadHash),
        };
        let segment_shift = 6 - encoded_part.len();
        let settings = encoded_part[3 - segment_shift];
        let salt = encoded_part[4 - segment_shift];
        let string_hash = encoded_part[5 - segment_shift].replace('+', "-");
        let hash = string_hash.as_str();
        let settings_part: Vec<&str> = settings.split(',').collect();
        let memory_cost: u32 = settings_part[0].split('=').collect::<Vec<&str>>()[1]
            .parse::<u32>()
            .map_err(|_| HasherError::BadHash)?;
        let time_cost: u32 = settings_part[1].split('=').collect::<Vec<&str>>()[1]
            .parse::<u32>()
            .map_err(|_| HasherError::BadHash)?;
        let parallelism: u32 = settings_part[2].split('=').collect::<Vec<&str>>()[1]
            .parse::<u32>()
            .map_err(|_| HasherError::BadHash)?;

        // Django's implementation expects a Base64-encoded salt, if it is not, return an error:
        if base64::decode_config(salt, base64::URL_SAFE_NO_PAD).is_err() {
            return Err(HasherError::InvalidArgon2Salt);
        }

        // Argon2 has a flexible hash length:
        let hash_length = match base64::decode_config(hash, base64::URL_SAFE_NO_PAD) {
            Ok(value) => value.len() as u32,
            Err(_) => return Ok(false),
        };

        Ok(crypto_utils::safe_eq(
            hash,
            crypto_utils::hash_argon2(
                password,
                salt,
                time_cost,
                memory_cost,
                parallelism,
                version,
                hash_length,
            ),
        ))
    }

    fn encode(&self, password: &str, salt: &str, iterations: u32) -> String {
        // - memory_cost: "kib" in Argon2's lingo.
        // - parallelism: "lanes" in Argon2's lingo.
        // - time_cost: "passes" in Argon2's lingo.
        let (memory_cost, parallelism, time_cost) = match iterations {
            1 => (512, 2, 2),
            2 => (102400, 8, 2),
            _ => unreachable!(),
        };
        let version = Version::Version13;
        let hash_length: u32 = 16;
        let hash = crypto_utils::hash_argon2(
            password,
            salt,
            time_cost,
            memory_cost,
            parallelism,
            version,
            hash_length,
        );
        format!(
            "argon2$argon2i$v=19$m={},t={},p={}${}${}",
            memory_cost, time_cost, parallelism, salt, hash
        )
    }
}

/// Hasher that uses the Scrypt function (new in Django 4.0).
#[cfg(feature = "with_scrypt")]
pub struct ScryptHasher;

#[cfg(feature = "with_scrypt")]
impl Hasher for ScryptHasher {
    fn verify(&self, password: &str, encoded: &str) -> Result<bool, HasherError> {
        let encoded_part: Vec<&str> = encoded.split('$').collect();
        let work_factor: u8 = encoded_part[1]
            .parse::<f32>()
            .ok_or(HasherError::BadHash)?
            .log2() as u8;
        let salt = encoded_part[2];
        let block_size = encoded_part[3].parse::<u32>().ok_or(HasherError::BadHash)?;
        let parallelism = encoded_part[4].parse::<u32>().ok_or(HasherError::BadHash)?;
        let hash = encoded_part[5];
        Ok(crypto_utils::safe_eq(
            hash,
            crypto_utils::hash_scrypt(password, salt, work_factor, block_size, parallelism),
        ))
    }

    fn encode(&self, password: &str, salt: &str, iterations: u32) -> String {
        // - work_factor: "n" in Scrypt's lingo.
        // - block_size: "r" in Scrypt's lingo.
        // - parallelism: "p" in Scrypt's lingo.
        let (work_factor, block_size, parallelism) = match iterations {
            1 => (14, 8, 1),
            _ => unreachable!(),
        };
        let hash = crypto_utils::hash_scrypt(password, salt, work_factor, block_size, parallelism);
        format!(
            "scrypt${}${}${}${}${}",
            2i32.pow(work_factor as u32),
            salt,
            block_size,
            parallelism,
            hash
        )
    }
}

/// Hasher that uses the bcrypt key-derivation function with the password padded with SHA256.
#[cfg(feature = "with_bcrypt")]
pub struct BCryptSHA256Hasher;

#[cfg(feature = "with_bcrypt")]
impl Hasher for BCryptSHA256Hasher {
    fn verify(&self, password: &str, encoded: &str) -> Result<bool, HasherError> {
        let bcrypt_encoded_part: Vec<&str> = encoded.splitn(2, '$').collect();
        let cost = bcrypt_encoded_part[1]
            .split('$')
            .nth(2)
            .ok_or(HasherError::BadHash)?
            .parse::<u32>()
            .map_err(|_| HasherError::InvalidIterations)?;
        if cost > BCRYPT_COST_DOS_LIMIT {
            return Err(HasherError::InvalidIterations);
        }
        let hash = bcrypt_encoded_part[1];
        let hashed_password = crypto_utils::hash_sha256(password);
        Ok(bcrypt::verify(&hashed_password, hash).unwrap_or(false))
    }

    fn encode(&self, password: &str, _: &str, iterations: u32) -> String {
        let hashed_password = crypto_utils::hash_sha256(password);
        let hash = bcrypt::hash(&hashed_password, iterations).unwrap();
        format!("{}${}", "bcrypt_sha256", hash)
    }
}

/// Hasher that uses the bcrypt key-derivation function without password padding.
#[cfg(feature = "with_bcrypt")]
pub struct BCryptHasher;

#[cfg(feature = "with_bcrypt")]
impl Hasher for BCryptHasher {
    fn verify(&self, password: &str, encoded: &str) -> Result<bool, HasherError> {
        let bcrypt_encoded_part: Vec<&str> = encoded.splitn(2, '$').collect();
        let cost = bcrypt_encoded_part[1]
            .split('$')
            .nth(2)
            .ok_or(HasherError::BadHash)?
            .parse::<u32>()
            .map_err(|_| HasherError::InvalidIterations)?;
        if cost > BCRYPT_COST_DOS_LIMIT {
            return Err(HasherError::InvalidIterations);
        }
        let hash = bcrypt_encoded_part[1];
        Ok(bcrypt::verify(password, hash).unwrap_or(false))
    }

    fn encode(&self, password: &str, _: &str, iterations: u32) -> String {
        let hash = bcrypt::hash(password, iterations).unwrap();
        format!("{}${}", "bcrypt", hash)
    }
}

/// Hasher that uses the SHA1 hashing function over the salted password.
#[cfg(feature = "with_legacy")]
pub struct SHA1Hasher;

#[cfg(feature = "with_legacy")]
impl Hasher for SHA1Hasher {
    fn verify(&self, password: &str, encoded: &str) -> Result<bool, HasherError> {
        let mut encoded_part = encoded.split('$').skip(1);
        let salt = encoded_part.next().ok_or(HasherError::BadHash)?;
        let hash = encoded_part.next().ok_or(HasherError::BadHash)?;
        Ok(crypto_utils::safe_eq(
            hash,
            crypto_utils::hash_sha1(password, salt),
        ))
    }

    fn encode(&self, password: &str, salt: &str, _: u32) -> String {
        let hash = crypto_utils::hash_sha1(password, salt);
        format!("{}${}${}", "sha1", salt, hash)
    }
}

/// Hasher that uses the MD5 hashing function over the salted password.
#[cfg(feature = "with_legacy")]
pub struct MD5Hasher;

#[cfg(feature = "with_legacy")]
impl Hasher for MD5Hasher {
    fn verify(&self, password: &str, encoded: &str) -> Result<bool, HasherError> {
        let mut encoded_part = encoded.split('$').skip(1);
        let salt = encoded_part.next().ok_or(HasherError::BadHash)?;
        let hash = encoded_part.next().ok_or(HasherError::BadHash)?;
        Ok(crypto_utils::safe_eq(
            hash,
            crypto_utils::hash_md5(password, salt),
        ))
    }

    fn encode(&self, password: &str, salt: &str, _: u32) -> String {
        let hash = crypto_utils::hash_md5(password, salt);
        format!("{}${}${}", "md5", salt, hash)
    }
}

/// Hasher that uses the SHA1 hashing function with no salting.
#[cfg(feature = "with_legacy")]
pub struct UnsaltedSHA1Hasher;

#[cfg(feature = "with_legacy")]
impl Hasher for UnsaltedSHA1Hasher {
    fn verify(&self, password: &str, encoded: &str) -> Result<bool, HasherError> {
        let mut encoded_part = encoded.split('$').skip(2);
        let hash = encoded_part.next().ok_or(HasherError::BadHash)?;
        Ok(crypto_utils::safe_eq(
            hash,
            crypto_utils::hash_sha1(password, ""),
        ))
    }

    fn encode(&self, password: &str, _: &str, _: u32) -> String {
        let hash = crypto_utils::hash_sha1(password, "");
        format!("{}$${}", "sha1", hash)
    }
}

/// Hasher that uses the MD5 hashing function with no salting.
#[cfg(feature = "with_legacy")]
pub struct UnsaltedMD5Hasher;

#[cfg(feature = "with_legacy")]
impl Hasher for UnsaltedMD5Hasher {
    fn verify(&self, password: &str, encoded: &str) -> Result<bool, HasherError> {
        Ok(crypto_utils::safe_eq(
            encoded,
            crypto_utils::hash_md5(password, ""),
        ))
    }

    fn encode(&self, password: &str, _: &str, _: u32) -> String {
        crypto_utils::hash_md5(password, "")
    }
}

/// Hasher that uses the UNIX's crypt(3) hash function.
#[cfg(feature = "with_legacy")]
pub struct CryptHasher;

#[cfg(feature = "with_legacy")]
impl Hasher for CryptHasher {
    fn verify(&self, password: &str, encoded: &str) -> Result<bool, HasherError> {
        let mut encoded_part = encoded.split('$').skip(2);
        let hash = encoded_part.next().ok_or(HasherError::BadHash)?;
        Ok(crypto_utils::safe_eq(
            hash,
            crypto_utils::hash_unix_crypt(password, hash),
        ))
    }

    fn encode(&self, password: &str, salt: &str, _: u32) -> String {
        let hash = crypto_utils::hash_unix_crypt(password, salt);
        format!("{}$${}", "crypt", hash)
    }
}
