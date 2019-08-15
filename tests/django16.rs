//! This is an almost line-by-line translation from the hashers' test from Django 1.8:
//! https://github.com/django/django/blob/d92b085/django/contrib/auth/tests/test_hashers.py
//! ...but only for the tests where the iterations differ from Django 1.9.

use djangohashers::*;

#[test]
#[cfg(feature = "with_pbkdf2")]
fn test_pbkdf2() {
    let django = Django {
        version: DjangoVersion::V1_6,
    };
    let encoded = django.make_password_with_settings("lètmein", "seasalt", Algorithm::PBKDF2);
    assert!(
        encoded
            == "pbkdf2_sha256$12000$seasalt$Ybw8zsFxqja97tY/o6G+Fy1ksY4U/Hw3DRrGED6Up4s="
                .to_string()
    );
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
#[cfg(feature = "with_pbkdf2")]
fn test_low_level_pbkdf2() {
    let django = Django {
        version: DjangoVersion::V1_6,
    };
    let encoded = django.make_password_with_settings("lètmein", "seasalt2", Algorithm::PBKDF2);
    assert!(
        encoded
            == "pbkdf2_sha256$12000$seasalt2$hlDLKsxgkgb1aeOppkM5atCYw5rPzAjCNQZ4NYyUROw="
                .to_string()
    );
    assert!(check_password("lètmein", &encoded).unwrap());
}

#[test]
#[cfg(feature = "with_pbkdf2")]
fn test_low_level_pbkdf2_sha1() {
    let django = Django {
        version: DjangoVersion::V1_6,
    };
    let encoded = django.make_password_with_settings("lètmein", "seasalt2", Algorithm::PBKDF2SHA1);
    assert!(encoded == "pbkdf2_sha1$12000$seasalt2$JeMRVfjjgtWw3/HzlnlfqBnQ6CA=".to_string());
    assert!(check_password("lètmein", &encoded).unwrap());
}
