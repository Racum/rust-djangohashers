//! This is an almost line-by-line translation from the hashers' test from Django 1.9:
//! https://github.com/django/django/blob/e403f22/tests/auth_tests/test_hashers.py
//! ...except for some cases that don't make sense in Rust, or in the scope of this library.

use djangohashers::*;

#[test]
#[cfg(feature = "with_pbkdf2")]
fn test_simple() {
    let django = Django {
        version: DjangoVersion::V1_9,
    };
    let encoded = django.make_password("lètmein");
    assert!(encoded.starts_with("pbkdf2_sha256$"));
    assert!(is_password_usable(&encoded));
    assert_eq!(check_password("lètmein", &encoded), Ok(true));
    assert_eq!(check_password("lètmeinz", &encoded), Ok(false));
    // Blank passwords
    let blank_encoded = django.make_password("");
    assert!(blank_encoded.starts_with("pbkdf2_sha256$"));
    assert!(is_password_usable(&blank_encoded));
    assert_eq!(check_password("", &blank_encoded), Ok(true));
    assert_eq!(check_password(" ", &blank_encoded), Ok(false));
}

#[test]
#[cfg(feature = "with_pbkdf2")]
fn test_pbkdf2() {
    let django = Django {
        version: DjangoVersion::V1_9,
    };
    let encoded = django.make_password_with_settings("lètmein", "seasalt", Algorithm::PBKDF2);
    assert_eq!(
        encoded,
        "pbkdf2_sha256$24000$seasalt$V9DfCAVoweeLwxC/L2mb+7swhzF0XYdyQMqmusZqiTc="
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
#[cfg(feature = "with_legacy")]
fn test_sha1() {
    let django = Django {
        version: DjangoVersion::V1_9,
    };
    let encoded = django.make_password_with_settings("lètmein", "seasalt", Algorithm::SHA1);
    assert_eq!(
        encoded,
        "sha1$seasalt$cff36ea83f5706ce9aa7454e63e431fc726b2dc8"
    );
    assert!(is_password_usable(&encoded));
    assert_eq!(check_password("lètmein", &encoded), Ok(true));
    assert_eq!(check_password("lètmeinz", &encoded), Ok(false));
    // Blank passwords
    let blank_encoded = django.make_password_with_settings("", "seasalt", Algorithm::SHA1);
    assert!(blank_encoded.starts_with("sha1$"));
    assert!(is_password_usable(&blank_encoded));
    assert_eq!(check_password("", &blank_encoded), Ok(true));
    assert_eq!(check_password(" ", &blank_encoded), Ok(false));
}

#[test]
#[cfg(feature = "with_legacy")]
fn test_md5() {
    let django = Django {
        version: DjangoVersion::V1_9,
    };
    let encoded = django.make_password_with_settings("lètmein", "seasalt", Algorithm::MD5);
    assert_eq!(encoded, "md5$seasalt$3f86d0d3d465b7b458c231bf3555c0e3");
    assert!(is_password_usable(&encoded));
    assert_eq!(check_password("lètmein", &encoded), Ok(true));
    assert_eq!(check_password("lètmeinz", &encoded), Ok(false));
    // Blank passwords
    let blank_encoded = django.make_password_with_settings("", "seasalt", Algorithm::MD5);
    assert!(blank_encoded.starts_with("md5$"));
    assert!(is_password_usable(&blank_encoded));
    assert_eq!(check_password("", &blank_encoded), Ok(true));
    assert_eq!(check_password(" ", &blank_encoded), Ok(false));
}

#[test]
#[cfg(feature = "with_legacy")]
fn test_unsalted_md5() {
    let django = Django {
        version: DjangoVersion::V1_9,
    };
    let encoded = django.make_password_with_settings("lètmein", "", Algorithm::UnsaltedMD5);
    assert_eq!(encoded, "88a434c88cca4e900f7874cd98123f43");
    assert!(is_password_usable(&encoded));
    assert_eq!(check_password("lètmein", &encoded), Ok(true));
    assert_eq!(check_password("lètmeinz", &encoded), Ok(false));
    // Blank passwords
    let blank_encoded = django.make_password_with_settings("", "", Algorithm::UnsaltedMD5);
    assert_eq!(check_password("", &blank_encoded), Ok(true));
    assert_eq!(check_password(" ", &blank_encoded), Ok(false));
}

#[test]
#[cfg(feature = "with_legacy")]
fn test_unsalted_sha1() {
    let django = Django {
        version: DjangoVersion::V1_9,
    };
    let encoded = django.make_password_with_settings("lètmein", "", Algorithm::UnsaltedSHA1);
    assert_eq!(encoded, "sha1$$6d138ca3ae545631b3abd71a4f076ce759c5700b");
    assert!(is_password_usable(&encoded));
    assert_eq!(check_password("lètmein", &encoded), Ok(true));
    assert_eq!(check_password("lètmeinz", &encoded), Ok(false));
    // Raw SHA1 isn't acceptable
    assert!(check_password("lètmein", "6d138ca3ae545631b3abd71a4f076ce759c5700b").is_err());
    // Blank passwords
    let blank_encoded = django.make_password_with_settings("", "", Algorithm::UnsaltedSHA1);
    assert!(blank_encoded.starts_with("sha1$"));
    assert!(is_password_usable(&blank_encoded));
    assert_eq!(check_password("", &blank_encoded), Ok(true));
    assert_eq!(check_password(" ", &blank_encoded), Ok(false));
}

#[test]
#[cfg(feature = "with_legacy")]
fn test_crypt() {
    let django = Django {
        version: DjangoVersion::V1_9,
    };
    let encoded = django.make_password_with_settings("lètmei", "ab", Algorithm::Crypt);
    assert_eq!(encoded, "crypt$$ab1Hv2Lg7ltQo");
    assert!(is_password_usable(&encoded));
    assert_eq!(check_password("lètmei", &encoded), Ok(true));
    assert_eq!(check_password("lètmeiz", &encoded), Ok(false));
    // Blank passwords
    let blank_encoded = django.make_password_with_settings("", "ab", Algorithm::Crypt);
    assert!(blank_encoded.starts_with("crypt$"));
    assert!(is_password_usable(&blank_encoded));
    assert_eq!(check_password("", &blank_encoded), Ok(true));
    assert_eq!(check_password(" ", &blank_encoded), Ok(false));
}

#[test]
#[cfg(feature = "with_bcrypt")]
fn test_bcrypt_sha256() {
    let django = Django {
        version: DjangoVersion::V1_9,
    };
    let encoded = django.make_password_with_settings("lètmein", "", Algorithm::BCryptSHA256);
    assert!(is_password_usable(&encoded));
    assert!(encoded.starts_with("bcrypt_sha256$"));
    assert_eq!(check_password("lètmein", &encoded), Ok(true));
    assert_eq!(check_password("lètmeinz", &encoded), Ok(false));
    // Verify that password truncation no longer works
    let password = "VSK0UYV6FFQVZ0KG88DYN9WADAADZO1CTSIVDJUNZSUML6IBX7LN7ZS3R5JGB3RGZ7VI7G7DJQ9NI8\
                    BQFSRPTG6UWTTVESA5ZPUN";
    let trunc_encoded = django.make_password_with_settings(password, "", Algorithm::BCryptSHA256);
    assert_eq!(check_password(password, &trunc_encoded), Ok(true));
    assert_eq!(check_password(&password[0..72], &trunc_encoded), Ok(false));
    // Blank passwords
    let blank_encoded = django.make_password_with_settings("", "", Algorithm::BCryptSHA256);
    assert!(is_password_usable(&blank_encoded));
    assert!(blank_encoded.starts_with("bcrypt_sha256$"));
    assert_eq!(check_password("", &blank_encoded), Ok(true));
    assert_eq!(check_password(" ", &blank_encoded), Ok(false));
}

#[test]
#[cfg(feature = "with_bcrypt")]
fn test_bcrypt() {
    let django = Django {
        version: DjangoVersion::V1_9,
    };
    let encoded = django.make_password_with_settings("lètmein", "", Algorithm::BCrypt);
    assert!(is_password_usable(&encoded));
    assert!(encoded.starts_with("bcrypt$"));
    assert_eq!(check_password("lètmein", &encoded), Ok(true));
    assert_eq!(check_password("lètmeinz", &encoded), Ok(false));
    // Blank passwords
    let blank_encoded = django.make_password_with_settings("", "", Algorithm::BCrypt);
    assert!(is_password_usable(&blank_encoded));
    assert!(blank_encoded.starts_with("bcrypt$"));
    assert_eq!(check_password("", &blank_encoded), Ok(true));
    assert_eq!(check_password(" ", &blank_encoded), Ok(false));
}

// This library does not fire upgrade callbacks:
// - test_bcrypt_upgrade

#[test]
fn test_unusable() {
    let encoded = "!Q24gQu9Sy3X1PJPCaEMTRrw5eLFWY8htI2FsqCbC"; // From make_password(None)
    assert!(encoded.len() == 41);
    assert!(!is_password_usable(encoded));
    assert!(check_password(encoded, encoded).is_err());
    assert!(check_password("!", encoded).is_err());
    assert!(check_password("", encoded).is_err());
    assert!(check_password("lètmein", encoded).is_err());
    assert!(check_password("lètmeinz", encoded).is_err());
}

// Scenario not possible during run time:
// - test_unspecified_password
// - test_bad_algorithm

#[test]
fn test_bad_encoded() {
    assert!(!is_password_usable("lètmein_badencoded"));
    assert!(!is_password_usable(""));
}

#[test]
#[cfg(feature = "with_pbkdf2")]
fn test_low_level_pbkdf2() {
    let django = Django {
        version: DjangoVersion::V1_9,
    };
    let encoded = django.make_password_with_settings("lètmein", "seasalt2", Algorithm::PBKDF2);
    assert_eq!(
        encoded,
        "pbkdf2_sha256$24000$seasalt2$TUDkfilKHVC7BkaKSZgIKhm0aTtXlmcw/5C1FeS/DPk="
    );
    assert_eq!(check_password("lètmein", &encoded), Ok(true));
}

#[test]
#[cfg(feature = "with_pbkdf2")]
fn test_low_level_pbkdf2_sha1() {
    let django = Django {
        version: DjangoVersion::V1_9,
    };
    let encoded = django.make_password_with_settings("lètmein", "seasalt2", Algorithm::PBKDF2SHA1);
    assert_eq!(
        encoded,
        "pbkdf2_sha1$24000$seasalt2$L37ETdd9trqrsJDwapU3P+2Edhg="
    );
    assert_eq!(check_password("lètmein", &encoded), Ok(true));
}

// This library does not fire upgrade callbacks:
// - test_upgrade
// - test_no_upgrade
// - test_no_upgrade_on_incorrect_pass
// - test_pbkdf2_upgrade
// - test_pbkdf2_upgrade_new_hasher

// Scenario not possible during run time:
// - test_load_library_no_algorithm
// - test_load_library_importerror
