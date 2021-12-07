//! This is an almost line-by-line translation from the hashers' test from Django 4.0:
//! https://github.com/django/django/blob/master/tests/auth_tests/test_hashers.py
//! ...but only for the tests where the iterations differ from Django 1.9.

use djangohashers::*;

#[test]
#[cfg(feature = "with_pbkdf2")]
fn test_pbkdf2() {
    let django = Django {
        version: DjangoVersion::V4_0,
    };
    let encoded = django.make_password_with_settings("lètmein", "seasalt", Algorithm::PBKDF2);
    assert_eq!(
        encoded,
        "pbkdf2_sha256$320000$seasalt$Toj2II2rBvFiGQcPmUml1Nlni2UtvyRWwz/jz4q6q/4="
    );
    assert!(is_password_usable(&encoded));
    assert_eq!(check_password("lètmein", &encoded), Ok(true));
    assert_eq!(check_password("lètmeinz", &encoded), Ok(false));
    // Blank passwords
    let blank_encoded = django.make_password_with_settings("", "seasalt", Algorithm::PBKDF2);
    assert!(blank_encoded.starts_with("pbkdf2_sha256$"));
    assert!(is_password_usable(&blank_encoded));
    assert_eq!(check_password("", &blank_encoded), Ok(true));
    assert_eq!(check_password(" ", &blank_encoded), Ok(false));
}

#[test]
#[cfg(feature = "with_pbkdf2")]
fn test_low_level_pbkdf2() {
    let django = Django {
        version: DjangoVersion::V4_0,
    };
    let encoded = django.make_password_with_settings("lètmein", "seasalt2", Algorithm::PBKDF2);
    assert_eq!(
        encoded,
        "pbkdf2_sha256$320000$seasalt2$BRr4pYNIQDsLFP+u4dzjs7pFuWJEin4lFMMoO9wBYvo="
    );
    assert_eq!(check_password("lètmein", &encoded), Ok(true));
}

#[test]
#[cfg(feature = "with_pbkdf2")]
fn test_low_level_pbkdf2_sha1() {
    let django = Django {
        version: DjangoVersion::V4_0,
    };
    let encoded = django.make_password_with_settings("lètmein", "seasalt2", Algorithm::PBKDF2SHA1);
    assert_eq!(
        encoded,
        "pbkdf2_sha1$320000$seasalt2$sDOkTvzV93jPWTRVxFGh50Jefo0="
    );
    assert_eq!(check_password("lètmein", &encoded), Ok(true));
}

#[test]
#[cfg(feature = "with_argon2")]
fn test_argon2() {
    let django = Django {
        version: DjangoVersion::V4_0,
    };
    let encoded = django.make_password_with_algorithm("lètmein", Algorithm::Argon2);
    assert!(is_password_usable(&encoded));
    assert!(encoded.starts_with("argon2$"));
    assert_eq!(check_password("lètmein", &encoded), Ok(true));
    assert_eq!(check_password("lètmeinz", &encoded), Ok(false));
    // Blank passwords
    let blank_encoded = django.make_password_with_algorithm("", Algorithm::Argon2);
    assert!(blank_encoded.starts_with("argon2$"));
    assert!(is_password_usable(&blank_encoded));
    assert_eq!(check_password("", &blank_encoded), Ok(true));
    assert_eq!(check_password(" ", &blank_encoded), Ok(false));
}

#[test]
#[cfg(feature = "with_scrypt")]
fn test_scrypt() {
    let django = Django {
        version: DjangoVersion::V4_0,
    };
    let encoded = django.make_password_with_settings("lètmein", "seasalt", Algorithm::Scrypt);
    assert_eq!(
        encoded,
        "scrypt$16384$seasalt$8$1$Qj3+9PPyRjSJIebHnG81TMjsqtaIGxNQG/aEB/NYafTJ7tibgfYz71m0ldQESkXFRkdVCBhhY8mx7rQwite/Pw=="
    );
    assert!(is_password_usable(&encoded));
    assert_eq!(check_password("lètmein", &encoded), Ok(true));
    assert_eq!(check_password("lètmeinz", &encoded), Ok(false));
    // Blank passwords
    let blank_encoded = django.make_password_with_settings("", "seasalt", Algorithm::Scrypt);
    assert!(blank_encoded.starts_with("scrypt$"));
    assert!(is_password_usable(&blank_encoded));
    assert_eq!(check_password("", &blank_encoded), Ok(true));
    assert_eq!(check_password(" ", &blank_encoded), Ok(false));
}
