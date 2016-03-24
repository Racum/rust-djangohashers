//! This is an almost line-by-line translation from the hashers' test from Django 1.8:
//! https://github.com/django/django/blob/feac4c3/tests/auth_tests/test_hashers.py
//! ...but only for the tests where the iterations differ from Django 1.9.

extern crate djangohashers;

use djangohashers::*;


#[test]
fn test_pbkdf2() {
    let django = Django {version: Version::V18};
    let encoded = django.make_password_with_settings("lètmein", "seasalt", Algorithm::PBKDF2);
    assert!(encoded ==
            "pbkdf2_sha256$20000$seasalt$oBSd886ysm3AqYun62DOdin8YcfbU1z9cksZSuLP9r0=".to_string());
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
    let django = Django {version: Version::V18};
    let encoded = django.make_password_with_settings("lètmein", "seasalt2", Algorithm::PBKDF2);
    assert!(encoded ==
            "pbkdf2_sha256$20000$seasalt2$Flpve/uAcyo6+IFI6YAhjeABGPVbRQjzHDxRhqxewgw="
                .to_string());
    assert!(check_password("lètmein", &encoded).unwrap());
}

#[test]
fn test_low_level_pbkdf2_sha1() {
    let django = Django {version: Version::V18};
    let encoded = django.make_password_with_settings("lètmein", "seasalt2", Algorithm::PBKDF2SHA1);
    assert!(encoded == "pbkdf2_sha1$20000$seasalt2$pJt86NmjAweBY1StBvxCu7l1o9o=".to_string());
    assert!(check_password("lètmein", &encoded).unwrap());
}
