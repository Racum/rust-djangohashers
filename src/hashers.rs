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
}

/// Hasher abstraction, providing methods to encode and verify hashes.
pub trait Hasher {
    /// Verifies a password against an encoded hash.
    fn verify(&self, password: &str, encoded: &str) -> Result<bool, HasherError>;
    /// Generates an encoded hash for a given password and salt.
    fn encode(&self, password: &str, hash: &str, iterations: u32) -> String;
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
