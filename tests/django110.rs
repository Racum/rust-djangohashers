//! This is an almost line-by-line translation from the hashers' test from Django 1.10:
//! https://github.com/django/django/blob/master/tests/auth_tests/test_hashers.py
//! ...but only for the tests where the iterations differ from Django 1.9.

use djangohashers::*;


#[test]
#[cfg(feature="with_pbkdf2")]
fn test_pbkdf2() {
    let django = Django {version: DjangoVersion::V1_10};
    let encoded = django.make_password_with_settings("lètmein", "seasalt", Algorithm::PBKDF2);
    assert!(encoded ==
            "pbkdf2_sha256$30000$seasalt$VrX+V8drCGo68wlvy6rfu8i1d1pfkdeXA4LJkRGJodY=".to_string());
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
#[cfg(feature="with_pbkdf2")]
fn test_low_level_pbkdf2() {
    let django = Django {version: DjangoVersion::V1_10};
    let encoded = django.make_password_with_settings("lètmein", "seasalt2", Algorithm::PBKDF2);
    assert!(encoded ==
            "pbkdf2_sha256$30000$seasalt2$a75qzbogeVhNFeMqhdgyyoqGKpIzYUo651sq57RERew="
                .to_string());
    assert!(check_password("lètmein", &encoded).unwrap());
}

#[test]
#[cfg(feature="with_pbkdf2")]
fn test_low_level_pbkdf2_sha1() {
    let django = Django {version: DjangoVersion::V1_10};
    let encoded = django.make_password_with_settings("lètmein", "seasalt2", Algorithm::PBKDF2SHA1);
    assert!(encoded == "pbkdf2_sha1$30000$seasalt2$pMzU1zNPcydf6wjnJFbiVKwgULc=".to_string());
    assert!(check_password("lètmein", &encoded).unwrap());
}

#[test]
#[cfg(feature="with_argon2")]
fn test_argon2() {
    let django = Django {version: DjangoVersion::V1_10};
    let encoded = django.make_password_with_algorithm("lètmein", Algorithm::Argon2);
    assert!(is_password_usable(&encoded));
    assert!(encoded.starts_with("argon2$"));
    assert!(check_password("lètmein", &encoded).unwrap());
    assert!(!check_password("lètmeinz", &encoded).unwrap());
    // Blank passwords
    let blank_encoded = django.make_password_with_algorithm("", Algorithm::Argon2);
    assert!(blank_encoded.starts_with("argon2$"));
    assert!(is_password_usable(&blank_encoded));
    assert!(check_password("", &blank_encoded).unwrap());
    assert!(!check_password(" ", &blank_encoded).unwrap());
}
