//! This is an almost line-by-line translation from the hashers' test from Django 2.2:
//! https://github.com/django/django/blob/master/tests/auth_tests/test_hashers.py
//! ...but only for the tests where the iterations differ from Django 1.9.

use djangohashers::*;

#[test]
#[cfg(feature = "with_pbkdf2")]
fn test_pbkdf2() {
    let django = Django {
        version: DjangoVersion::V2_2,
    };
    let encoded = django.make_password_with_settings("lètmein", "seasalt", Algorithm::PBKDF2);
    assert_eq!(
        encoded,
        "pbkdf2_sha256$150000$seasalt$71l36B3C2UesFoWz5oshQ1SSTtCLnDO5RMysCfljq5o="
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
        version: DjangoVersion::V2_2,
    };
    let encoded = django.make_password_with_settings("lètmein", "seasalt2", Algorithm::PBKDF2);
    assert_eq!(
        encoded,
        "pbkdf2_sha256$150000$seasalt2$5xGh/XsAm2L9fQXShAI1qf739n97YlTaaLY8/t6Ms7o="
    );
    assert_eq!(check_password("lètmein", &encoded), Ok(true));
}

#[test]
#[cfg(feature = "with_pbkdf2")]
fn test_low_level_pbkdf2_sha1() {
    let django = Django {
        version: DjangoVersion::V2_2,
    };
    let encoded = django.make_password_with_settings("lètmein", "seasalt2", Algorithm::PBKDF2SHA1);
    assert_eq!(
        encoded,
        "pbkdf2_sha1$150000$seasalt2$lIjyT2rG1gVh5rdCmuAEoHwQtQE="
    );
    assert_eq!(check_password("lètmein", &encoded), Ok(true));
}
