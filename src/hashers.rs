use crypto_utils;

// Django 1.9 defaults:
const PBKDF2_ITERATIONS: u32 = 24000;
const BCRYPT_ROUNDS: u32 = 12;

#[derive(PartialEq, Debug)]
pub enum HasherError {
    UnknownAlgorithm,
    EmptyHash,
    InvalidIterations,
}

pub trait Hasher {
    fn verify(&self, password: &str, encoded: &str) -> Result<bool, HasherError>;
    fn encode(&self, password: &str, hash: &str) -> String;
}

// List of Hashers:

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

    fn encode(&self, password: &str, salt: &str) -> String {
        let iterations = PBKDF2_ITERATIONS;
        let hash = crypto_utils::hash_pbkdf2_sha256(password, salt, iterations);
        format!("{}${}${}${}", "pbkdf2_sha256", iterations, salt, hash)
    }
}


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

    fn encode(&self, password: &str, salt: &str) -> String {
        let iterations = PBKDF2_ITERATIONS;
        let hash = crypto_utils::hash_pbkdf2_sha1(password, salt, iterations);
        format!("{}${}${}${}", "pbkdf2_sha1", iterations, salt, hash)
    }
}


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

    fn encode(&self, password: &str, _: &str) -> String {
        let hashed_password = crypto_utils::hash_sha256(password);
        let hash = crypto_utils::hash_bcrypt(&hashed_password, BCRYPT_ROUNDS).unwrap();
        format!("{}${}", "bcrypt_sha256", hash)
    }
}


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

    fn encode(&self, password: &str, _: &str) -> String {
        let hash = crypto_utils::hash_bcrypt(password, BCRYPT_ROUNDS).unwrap();
        format!("{}${}", "bcrypt", hash)
    }
}


pub struct SHA1Hasher;

impl Hasher for SHA1Hasher {
    fn verify(&self, password: &str, encoded: &str) -> Result<bool, HasherError> {
        let encoded_part: Vec<&str> = encoded.split("$").collect();
        let salt = encoded_part[1];
        let hash = encoded_part[2];
        Ok(hash == crypto_utils::hash_sha1(password, salt))
    }

    fn encode(&self, password: &str, salt: &str) -> String {
        let hash = crypto_utils::hash_sha1(password, salt);
        format!("{}${}${}", "sha1", salt, hash)
    }
}


pub struct MD5Hasher;

impl Hasher for MD5Hasher {
    fn verify(&self, password: &str, encoded: &str) -> Result<bool, HasherError> {
        let encoded_part: Vec<&str> = encoded.split("$").collect();
        let salt = encoded_part[1];
        let hash = encoded_part[2];
        Ok(hash == crypto_utils::hash_md5(password, salt))
    }

    fn encode(&self, password: &str, salt: &str) -> String {
        let hash = crypto_utils::hash_md5(password, salt);
        format!("{}${}${}", "md5", salt, hash)
    }
}


pub struct UnsaltedSHA1Hasher;

impl Hasher for UnsaltedSHA1Hasher {
    fn verify(&self, password: &str, encoded: &str) -> Result<bool, HasherError> {
        let encoded_part: Vec<&str> = encoded.split("$").collect();
        let hash = encoded_part[2];
        Ok(hash == crypto_utils::hash_sha1(password, ""))
    }

    fn encode(&self, password: &str, _: &str) -> String {
        let hash = crypto_utils::hash_sha1(password, "");
        format!("{}$${}", "sha1", hash)
    }
}


pub struct UnsaltedMD5Hasher;

impl Hasher for UnsaltedMD5Hasher {
    fn verify(&self, password: &str, encoded: &str) -> Result<bool, HasherError> {
        Ok(encoded == crypto_utils::hash_md5(password, ""))
    }

    fn encode(&self, password: &str, _: &str) -> String {
        crypto_utils::hash_md5(password, "").to_string()
    }
}
