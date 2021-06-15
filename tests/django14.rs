//! This is an almost line-by-line translation from the hashers' test from Django 1.4:
//! https://github.com/django/django/blob/2591fb8/django/contrib/auth/tests/hashers.py
//! ...but only for the tests where the iterations differ from Django 1.9.

use djangohashers::*;

#[test]
#[cfg(feature = "with_pbkdf2")]
fn test_pbkdf2() {
    let django = Django {
        version: DjangoVersion::V1_4,
    };
    let encoded = django.make_password_with_settings("letmein", "seasalt", Algorithm::PBKDF2);
    assert_eq!(
        encoded,
        "pbkdf2_sha256$10000$seasalt$FQCNpiZpTb0zub+HBsH6TOwyRxJ19FwvjbweatNmK/Y="
    );
    assert!(is_password_usable(&encoded));
    assert_eq!(check_password("letmein", &encoded), Ok(true));
    assert_eq!(check_password("letmeinz", &encoded), Ok(false));
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
        version: DjangoVersion::V1_4,
    };
    let encoded = django.make_password_with_settings("letmein", "seasalt", Algorithm::PBKDF2);
    assert_eq!(
        encoded,
        "pbkdf2_sha256$10000$seasalt$FQCNpiZpTb0zub+HBsH6TOwyRxJ19FwvjbweatNmK/Y="
    );
    assert_eq!(check_password("letmein", &encoded), Ok(true));
}

#[test]
#[cfg(feature = "with_pbkdf2")]
fn test_low_level_pbkdf2_sha1() {
    let django = Django {
        version: DjangoVersion::V1_4,
    };
    let encoded = django.make_password_with_settings("letmein", "seasalt", Algorithm::PBKDF2SHA1);
    assert_eq!(
        encoded,
        "pbkdf2_sha1$10000$seasalt$91JiNKgwADC8j2j86Ije/cc4vfQ="
    );
    assert_eq!(check_password("letmein", &encoded), Ok(true));
}
