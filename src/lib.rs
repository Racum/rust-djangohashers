extern crate rustc_serialize;
extern crate crypto;
extern crate bcrypt;

use rustc_serialize::base64::{STANDARD, ToBase64};
use crypto::digest::Digest;
use crypto::hmac::Hmac;
use crypto::sha2::Sha256;
use crypto::sha1::Sha1;
use crypto::md5::Md5;
use crypto::pbkdf2::pbkdf2;
use bcrypt::hash as bcrypt_hash;
use bcrypt::verify as bcrypt_verify;


#[derive(Debug)]
pub enum HasherError {
    UnknownAlgorithm,
    InvalidEncoding,
    InvalidIterations,
}

// No "Crypt": it is not recommended for being too weak and not available in all platforms.
pub enum Algorithm {
    PBKDF2,
    PBKDF2SHA1,
    BCryptSHA256,
    BCrypt,
    SHA1,
    MD5,
    UnsaltedSHA1,
    UnsaltedMD5,
}

#[allow(unused_variables)]
pub fn is_password_usable(encoded: &str) -> bool {
    true
}

fn hash_pbkdf2_sha256(password: &str, salt: &str, iterations: u32) -> String {
    let mut mac = Hmac::new(Sha256::new(), &password.as_bytes());
    let mut result = [0u8; 32];
    pbkdf2(&mut mac, &salt.as_bytes(), iterations, &mut result);
    result.to_base64(STANDARD)
}

fn hash_pbkdf2_sha1(password: &str, salt: &str, iterations: u32) -> String {
    let mut mac = Hmac::new(Sha1::new(), &password.as_bytes());
    let mut result = [0u8; 20];
    pbkdf2(&mut mac, &salt.as_bytes(), iterations, &mut result);
    result.to_base64(STANDARD)
}

fn hash_sha1(password: &str, salt: &str) -> String {
    let mut sha = Sha1::new();
    sha.input_str(salt);
    sha.input_str(password);
    sha.result_str()
}

fn hash_md5(password: &str, salt: &str) -> String {
    let mut md5 = Md5::new();
    md5.input_str(salt);
    md5.input_str(password);
    md5.result_str()
}

pub fn check_password(password: &str, encoded: &str) -> Result<bool, HasherError> {

    let encoded_part: Vec<&str> = encoded.split("$").collect();

    let salt: &str;
    let hash: &str;
    let mut iterations: u32 = 0;

    // if encoded_part[0] == "bcrypt_sha256" || encoded_part[0] == "bcrypt" {
    if encoded_part[0].starts_with("bcrypt") {
        let bcrypt_encoded_part: Vec<&str> = encoded.splitn(2, "$").collect();
        salt = "";
        hash = bcrypt_encoded_part[1];
    } else {
        match encoded_part.len() {
            4 => {
                salt = encoded_part[2];
                hash = encoded_part[3];
                match encoded_part[1].parse::<u32>() {
                    Ok(n) => {
                        iterations = n;
                    }
                    Err(_) => {
                        return Err(HasherError::InvalidIterations);
                    }
                }
            }
            3 => {
                salt = encoded_part[1];
                hash = encoded_part[2];
            }
            1 => {
                // UnsaltedMD5
                salt = "";
                hash = encoded_part[0];
                return Ok(hash == hash_md5(password, salt));
            }
            _ => {
                return Err(HasherError::InvalidEncoding);
            }
        }
    }

    match encoded_part[0] {
        "pbkdf2_sha256" => {
            return Ok(hash == hash_pbkdf2_sha256(password, salt, iterations));
        }
        "pbkdf2_sha1" => {
            return Ok(hash == hash_pbkdf2_sha1(password, salt, iterations));
        }
        "bcrypt_sha256" => {
            let mut sha = Sha256::new();
            sha.input_str(password);
            match bcrypt_verify(&sha.result_str(), hash) {
                Ok(valid) => {
                    return Ok(valid);
                }
                Err(_) => {
                    return Ok(false);
                }
            }
        }
        "bcrypt" => {
            match bcrypt_verify(password, hash) {
                Ok(valid) => {
                    return Ok(valid);
                }
                Err(_) => {
                    return Ok(false);
                }
            }
        }
        "sha1" => {
            return Ok(hash == hash_sha1(password, salt));
        }
        "md5" => {
            return Ok(hash == hash_md5(password, salt));
        }
        _ => {
            return Err(HasherError::UnknownAlgorithm);
        }
    }

}

/// Turn a plain-text password into a hash for database storage.
pub fn make_password_with_settings(password: &str, salt: &str, algorithm: Algorithm) -> String {
    match algorithm {
        Algorithm::PBKDF2 => {
            let iterations = 24000;
            let hash = hash_pbkdf2_sha256(password, salt, iterations);
            format!("{}${}${}${}", "pbkdf2_sha256", iterations, salt, hash)
        }
        Algorithm::PBKDF2SHA1 => {
            let iterations = 24000;
            let hash = hash_pbkdf2_sha1(password, salt, iterations);
            format!("{}${}${}${}", "pbkdf2_sha1", iterations, salt, hash)
        }
        Algorithm::BCryptSHA256 => {
            let mut sha = Sha256::new();
            sha.input_str(password);
            let hash = bcrypt_hash(&sha.result_str(), 12).unwrap();
            format!("{}${}", "bcrypt_sha256", hash)
        }
        Algorithm::BCrypt => {
            let hash = bcrypt_hash(password, 12).unwrap();
            format!("{}${}", "bcrypt", hash)
        }
        Algorithm::SHA1 => {
            let hash = hash_sha1(password, salt);
            format!("{}${}${}", "sha1", salt, hash)
        }
        Algorithm::MD5 => {
            let hash = hash_md5(password, salt);
            format!("{}${}${}", "md5", salt, hash)
        }
        Algorithm::UnsaltedSHA1 => {
            let hash = hash_sha1(password, "");
            format!("{}$${}", "sha1", hash)
        }
        Algorithm::UnsaltedMD5 => hash_md5(password, salt).to_string(),
    }
}

pub fn make_password_with_algorithm(password: &str, algorithm: Algorithm) -> String {
    make_password_with_settings(password, "seasalt", algorithm)
}

pub fn make_password(password: &str) -> String {
    make_password_with_algorithm(password, Algorithm::PBKDF2)
}
