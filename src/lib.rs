extern crate rand;

use rand::Rng;
mod crypto_utils;
mod hashers;

pub use hashers::*;


#[derive(PartialEq)]
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

fn identify_hasher(encoded: &str) -> Option<Algorithm> {
    if (encoded.len() == 32 && !encoded.contains("$")) ||
       (encoded.len() == 37 && encoded.starts_with("md5$$")) {
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
            _ => None,
        }
    }
}

fn get_hasher(algorithm: Algorithm) -> Box<Hasher + 'static> {
    match algorithm {
        Algorithm::PBKDF2 => Box::new(PBKDF2Hasher),
        Algorithm::PBKDF2SHA1 => Box::new(PBKDF2SHA1Hasher),
        Algorithm::BCryptSHA256 => Box::new(BCryptSHA256Hasher),
        Algorithm::BCrypt => Box::new(BCryptHasher),
        Algorithm::SHA1 => Box::new(SHA1Hasher),
        Algorithm::MD5 => Box::new(MD5Hasher),
        Algorithm::UnsaltedSHA1 => Box::new(UnsaltedSHA1Hasher),
        Algorithm::UnsaltedMD5 => Box::new(UnsaltedMD5Hasher),
    }
}

pub fn is_password_usable(encoded: &str) -> bool {
    match identify_hasher(encoded) {
        Some(_) => !(encoded == "" || encoded.starts_with("!")),
        None => false,
    }
}

pub fn check_password(password: &str, encoded: &str) -> Result<bool, HasherError> {
    if encoded == "" {
        return Err(HasherError::EmptyHash);
    }
    match identify_hasher(encoded) {
        Some(algorithm) => {
            let hasher = get_hasher(algorithm);
            hasher.verify(password, encoded)
        }
        None => Err(HasherError::UnknownAlgorithm),
    }
}

pub fn check_password_tolerant(password: &str, encoded: &str) -> bool {
    match check_password(password, encoded) {
        Ok(valid) => valid,
        Err(_) => false,
    }
}

pub fn make_password_with_settings(password: &str, salt: &str, algorithm: Algorithm) -> String {
    let hasher = get_hasher(algorithm);
    hasher.encode(password, salt)
}

pub fn make_password_with_algorithm(password: &str, algorithm: Algorithm) -> String {
    let salt = rand::thread_rng().gen_ascii_chars().take(12).collect::<String>();
    make_password_with_settings(password, &salt, algorithm)
}

pub fn make_password(password: &str) -> String {
    make_password_with_algorithm(password, Algorithm::PBKDF2)
}

#[test]
fn test_identify_hasher() {
    // Good hashes:
    assert!(identify_hasher("pbkdf2_sha256$24000$KQ8zeK6wKRuR$cmhbSt1XVKuO4FGd9+AX8qSBD4Z0395\
                             nZatXTJpEtTY=")
                .unwrap() == Algorithm::PBKDF2);
    assert!(identify_hasher("pbkdf2_sha1$24000$KQ8zeK6wKRuR$tSJh4xdxfMJotlxfkCGjTFpGYZU=")
                .unwrap() == Algorithm::PBKDF2SHA1);
    assert!(identify_hasher("sha1$KQ8zeK6wKRuR$f83371bca01fa6089456e673ccfb17f42d810b00")
                .unwrap() == Algorithm::SHA1);
    assert!(identify_hasher("md5$KQ8zeK6wKRuR$0137e4d74cb2d9ed9cb1a5f391f6175e").unwrap() ==
            Algorithm::MD5);
    assert!(identify_hasher("7cf6409a82cd4c8b96a9ecf6ad679119").unwrap() == Algorithm::UnsaltedMD5);
    assert!(identify_hasher("md5$$7cf6409a82cd4c8b96a9ecf6ad679119").unwrap() ==
            Algorithm::UnsaltedMD5);
    assert!(identify_hasher("sha1$$22e6217f026c7a395f0840c1ffbdb163072419e7").unwrap() ==
            Algorithm::UnsaltedSHA1);
    assert!(identify_hasher("bcrypt_sha256$$2b$12$LZSJchsWG/DrBy1erNs4eeYo6tZNlLFQmONdxN9HPes\
                             a1EyXVcTXK")
                .unwrap() == Algorithm::BCryptSHA256);
    assert!(identify_hasher("bcrypt$$2b$12$LZSJchsWG/DrBy1erNs4ee31eJ7DaWiuwhDOC7aqIyqGGggfu6\
                             Y/.")
                .unwrap() == Algorithm::BCrypt);
    // Bad hashes:
    assert!(identify_hasher("").is_none());
    assert!(identify_hasher("password").is_none());
    assert!(identify_hasher("7cf6409a82cd4c8b96a9ecf6ad6791190").is_none());
    assert!(identify_hasher("blah$KQ8zeK6wKRuR$f83371bca01fa6089456e673ccfb17f42d810b00")
                .is_none());
}
