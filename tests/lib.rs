extern crate djangohashers;

use djangohashers::*;

static PASSWORD: &'static str = "ExjGmyUT73bFoT";
static SALT: &'static str = "KQ8zeK6wKRuR";

#[test]
fn test_pbkdf2_sha256() {
    let encoded = make_password_core(PASSWORD, SALT, Algorithm::PBKDF2, Version::V19);
    let h = "pbkdf2_sha256$24000$KQ8zeK6wKRuR$cmhbSt1XVKuO4FGd9+AX8qSBD4Z0395nZatXTJpEtTY=";
    assert!(encoded == h.to_string());
    assert!(check_password(PASSWORD, &encoded).unwrap());
}

#[test]
fn test_pbkdf2_sha1() {
    let encoded = make_password_core(PASSWORD, SALT, Algorithm::PBKDF2SHA1, Version::V19);
    let h = "pbkdf2_sha1$24000$KQ8zeK6wKRuR$tSJh4xdxfMJotlxfkCGjTFpGYZU=";
    assert!(encoded == h.to_string());
    assert!(check_password(PASSWORD, &encoded).unwrap());
}

#[test]
fn test_sha1() {
    let encoded = make_password_core(PASSWORD, SALT, Algorithm::SHA1, Version::V19);
    let h = "sha1$KQ8zeK6wKRuR$f83371bca01fa6089456e673ccfb17f42d810b00";
    assert!(encoded == h.to_string());
    assert!(check_password(PASSWORD, &encoded).unwrap());
}

#[test]
fn test_md5() {
    let encoded = make_password_core(PASSWORD, SALT, Algorithm::MD5, Version::V19);
    let h = "md5$KQ8zeK6wKRuR$0137e4d74cb2d9ed9cb1a5f391f6175e";
    assert!(encoded == h.to_string());
    assert!(check_password(PASSWORD, &encoded).unwrap());
}

#[test]
fn test_unsalted_md5() {
    let encoded = make_password_core(PASSWORD, "", Algorithm::UnsaltedMD5, Version::V19);
    let h = "7cf6409a82cd4c8b96a9ecf6ad679119";
    assert!(encoded == h.to_string());
    assert!(check_password(PASSWORD, &encoded).unwrap());
}

#[test]
fn test_unsalted_sha1() {
    let encoded = make_password_core(PASSWORD, "", Algorithm::UnsaltedSHA1, Version::V19);
    let h = "sha1$$22e6217f026c7a395f0840c1ffbdb163072419e7";
    assert!(encoded == h.to_string());
    assert!(check_password(PASSWORD, &encoded).unwrap());
}

#[test]
fn test_bcrypt_sha256() {
    let encoded = make_password_core(PASSWORD, "", Algorithm::BCryptSHA256, Version::V19);
    assert!(check_password(PASSWORD, &encoded).unwrap());
    let h = "bcrypt_sha256$$2b$12$LZSJchsWG/DrBy1erNs4eeYo6tZNlLFQmONdxN9HPesa1EyXVcTXK";
    assert!(check_password(PASSWORD, h).unwrap());
}

#[test]
fn test_bcrypt() {
    let encoded = make_password_core(PASSWORD, "", Algorithm::BCrypt, Version::V19);
    assert!(check_password(PASSWORD, &encoded).unwrap());
    let h = "bcrypt$$2b$12$LZSJchsWG/DrBy1erNs4ee31eJ7DaWiuwhDOC7aqIyqGGggfu6Y/.";
    assert!(check_password(PASSWORD, h).unwrap());
}

#[test]
fn test_crypt() {
    let encoded = make_password_core(PASSWORD, SALT, Algorithm::Crypt, Version::V19);
    assert!(check_password(PASSWORD, &encoded).unwrap());
    let h = "crypt$$KQW3RFkgPSuuA";
    assert!(check_password(PASSWORD, h).unwrap());
}

#[test]
fn test_argon2() {
    let encoded = make_password_core(PASSWORD, SALT, Algorithm::Argon2, Version::V110);
    assert!(check_password(PASSWORD, &encoded).unwrap());
    let h = "argon2$argon2i$v=19$m=512,t=2,p=2$S1E4emVLNndLUnVS$RUET3AC8iXvcVPD2TRjvVQ";
    assert!(check_password(PASSWORD, h).unwrap());
}

#[test]
fn test_argon2_old() {
    // From https://github.com/django/django/blob/master/tests/auth_tests/test_hashers.py
    let old_from_django = "argon2$argon2i$m=8,t=1,p=1$c29tZXNhbHQ$gwQOXSNhxiOxPOA0+PY10P9QFO4NAYysnqRt1GSQLE55m+2GYDt9FEjPMHhP2Cuf0nOEXXMocVrsJAtNSsKyfg";
    assert!(check_password("secret", old_from_django).unwrap());
    assert!(!check_password("wrong", old_from_django).unwrap());
    // From https://github.com/hynek/argon2_cffi/blob/master/tests/test_low_level.py
    // ...prefixed with "argon2$", emulating Django's format:
    let old_from_argon2_cffi = "argon2$argon2i$m=65536,t=2,p=4$c29tZXNhbHQAAAAAAAAAAA$QWLzI4TY9HkL2ZTLc8g6SinwdhZewYrzz9zxCo0bkGY";
    assert!(check_password("password", old_from_argon2_cffi).unwrap());
    assert!(!check_password("wrong", old_from_argon2_cffi).unwrap());
}

#[test]
fn test_is_password_usable() {
    // Good hashes:
    assert!(is_password_usable("pbkdf2_sha1$24000$KQ8zeK6wKRuR$tSJh4xdxfMJotlxfkCGjTFpGYZU="));
    assert!(is_password_usable("7cf6409a82cd4c8b96a9ecf6ad679119"));
    // Bad hashes:
    assert!(!is_password_usable(""));
    assert!(!is_password_usable("password"));
    assert!(!is_password_usable("!cf6409a82cd4c8b96a9ecf6ad679119"));
}

#[test]
fn test_check_password_tolerant() {
    let negative = "pbkdf2_sha256$-24000$KQ8zeK6wKRuR$cmhbSt1XVKuO4FGd9+AX8qSBD4Z0395nZatXTJpEtTY=";
    assert!(!check_password_tolerant(PASSWORD, negative));
    let nan = "pbkdf2_sha256$NaN$KQ8zeK6wKRuR$cmhbSt1XVKuO4FGd9+AX8qSBD4Z0395nZatXTJpEtTY=";
    assert!(!check_password_tolerant(PASSWORD, nan));
    let rot13 = "rot13$1$KQ8zeK6wKRuR$cmhbSt1XVKuO4FGd9+AX8qSBD4Z0395nZatXTJpEtTY=";
    assert!(!check_password_tolerant(PASSWORD, rot13));
    assert!(!check_password_tolerant(PASSWORD, ""));
}

#[test]
fn test_errors() {
    let negative = "pbkdf2_sha256$-24000$KQ8zeK6wKRuR$cmhbSt1XVKuO4FGd9+AX8qSBD4Z0395nZatXTJpEtTY=";
    assert!(check_password(PASSWORD, negative) == Err(HasherError::InvalidIterations));
    let nan = "pbkdf2_sha256$NaN$KQ8zeK6wKRuR$cmhbSt1XVKuO4FGd9+AX8qSBD4Z0395nZatXTJpEtTY=";
    assert!(check_password(PASSWORD, nan) == Err(HasherError::InvalidIterations));
    let rot13 = "rot13$1$KQ8zeK6wKRuR$cmhbSt1XVKuO4FGd9+AX8qSBD4Z0395nZatXTJpEtTY=";
    assert!(check_password(PASSWORD, rot13) == Err(HasherError::UnknownAlgorithm));
    assert!(check_password(PASSWORD, "") == Err(HasherError::EmptyHash));
}
