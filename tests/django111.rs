//! This is an almost line-by-line translation from the hashers' test from Django 1.11:
//! https://github.com/django/django/blob/master/tests/auth_tests/test_hashers.py
//! ...but only for the tests where the iterations differ from Django 1.9.

extern crate djangohashers;

use djangohashers::*;


#[test]
fn test_pbkdf2() {
    let django = Django {version: Version::V111};
    let encoded = django.make_password_with_settings("lètmein", "seasalt", Algorithm::PBKDF2);
    assert!(encoded ==
            "pbkdf2_sha256$36000$seasalt$mEUPPFJkT/xtwDU8rB7Q+puHRZnR07WRjerTkt/3HI0=".to_string());
    assert!(is_password_usable(&encoded));
    assert!(check_password("lètmein", &encoded).unwrap());
    assert!(!check_password("lètmeinz", &encoded).unwrap());
    // Blank passwords
    let blank_encoded = django.make_password_with_settings("", "seasalt", Algorithm::PBKDF2);
    assert!(blank_encoded.starts_with("pbkdf2_sha256$"));
    assert!(is_password_usable(&blank_encoded));
    assert!(check_password("", &blank_encoded).unwrap());
    assert!(!check_password(" ", &blank_encoded).unwrap());
}

#[test]
fn test_low_level_pbkdf2() {
    let django = Django {version: Version::V111};
    let encoded = django.make_password_with_settings("lètmein", "seasalt2", Algorithm::PBKDF2);
    assert!(encoded ==
            "pbkdf2_sha256$36000$seasalt2$QkIBVCvGmTmyjPJ5yox2y/jQB8isvgUNK98FxOU1UYo="
                .to_string());
    assert!(check_password("lètmein", &encoded).unwrap());
}

#[test]
fn test_low_level_pbkdf2_sha1() {
    let django = Django {version: Version::V111};
    let encoded = django.make_password_with_settings("lètmein", "seasalt2", Algorithm::PBKDF2SHA1);
    assert!(encoded == "pbkdf2_sha1$36000$seasalt2$GoU+9AubJ/xRkO0WD1Xf3WPxWfE=".to_string());
    assert!(check_password("lètmein", &encoded).unwrap());
}
