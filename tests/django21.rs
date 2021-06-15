//! This is an almost line-by-line translation from the hashers' test from Django 2.1:
//! https://github.com/django/django/blob/master/tests/auth_tests/test_hashers.py
//! ...but only for the tests where the iterations differ from Django 1.9.

use djangohashers::*;

#[test]
#[cfg(feature = "with_pbkdf2")]
fn test_pbkdf2() {
    let django = Django {
        version: DjangoVersion::V2_1,
    };
    let encoded = django.make_password_with_settings("lètmein", "seasalt", Algorithm::PBKDF2);
    assert_eq!(
        encoded,
        "pbkdf2_sha256$120000$seasalt$fsgWMpOXin7ZAmi4j+7XjKCZ4JCvxJTGiwwDrawRqSc="
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
        version: DjangoVersion::V2_1,
    };
    let encoded = django.make_password_with_settings("lètmein", "seasalt2", Algorithm::PBKDF2);
    assert_eq!(
        encoded,
        "pbkdf2_sha256$120000$seasalt2$FRWVLZaxRXtbVIkhYdTQc/tE7JF/s5tU/4O4VhB94ig="
    );
    assert_eq!(check_password("lètmein", &encoded), Ok(true));
}

#[test]
#[cfg(feature = "with_pbkdf2")]
fn test_low_level_pbkdf2_sha1() {
    let django = Django {
        version: DjangoVersion::V2_1,
    };
    let encoded = django.make_password_with_settings("lètmein", "seasalt2", Algorithm::PBKDF2SHA1);
    assert_eq!(
        encoded,
        "pbkdf2_sha1$120000$seasalt2$6kIwMgg3rEEwDAQY/CB9VUVtEiI="
    );
    assert_eq!(check_password("lètmein", &encoded), Ok(true));
}
