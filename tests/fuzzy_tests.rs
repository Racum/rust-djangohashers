#[cfg(feature = "fuzzy_tests")]
mod fuzzy_tests {
    use djangohashers::*;
    use quickcheck::{quickcheck, TestResult};

    #[cfg(feature = "with_argon2")]
    extern crate base64;
    #[cfg(feature = "with_argon2")]
    use self::base64::{encode_config, URL_SAFE_NO_PAD};

    fn check_algorithm(pwd: String, salt: String, algorithm: Algorithm) -> TestResult {
        if !VALID_SALT_RE.is_match(&salt) {
            return TestResult::discard();
        }

        TestResult::from_bool(check_password_tolerant(
            &pwd,
            &make_password_with_settings(&pwd, &salt, algorithm),
        ))
    }

    #[cfg(feature = "with_pbkdf2")]
    quickcheck! {
        fn test_fuzzy_pbkdf2(pwd: String, salt: String) -> TestResult {
            check_algorithm(pwd, salt, Algorithm::PBKDF2)
        }
    }

    #[cfg(feature = "with_pbkdf2")]
    quickcheck! {
        fn test_fuzzy_pbkdf2sha1(pwd: String, salt: String) -> TestResult {
            check_algorithm(pwd, salt, Algorithm::PBKDF2SHA1)
        }
    }

    #[cfg(feature = "with_argon2")]
    quickcheck! {
        fn test_fuzzy_argon2(pwd: String, salt: String) -> TestResult {
            check_algorithm(pwd, encode_config(salt.as_bytes(), URL_SAFE_NO_PAD), Algorithm::Argon2)
        }
    }

    #[cfg(feature = "with_bcrypt")]
    quickcheck! {
        fn test_fuzzy_bcryptsha256(pwd: String, salt: String) -> TestResult {
            check_algorithm(pwd, salt, Algorithm::BCryptSHA256)
        }
    }

    #[cfg(feature = "with_bcrypt")]
    quickcheck! {
        fn test_fuzzy_bcrypt(pwd: String, salt: String) -> TestResult {
            if pwd.contains('\0') || pwd.len() >= 72 {
                return TestResult::discard();
            }

            check_algorithm(pwd, salt, Algorithm::BCrypt)
        }
    }

    #[cfg(feature = "with_legacy")]
    quickcheck! {
        fn test_fuzzy_sha1(pwd: String, salt: String) -> TestResult {
            check_algorithm(pwd, salt, Algorithm::SHA1)
        }
    }

    #[cfg(feature = "with_legacy")]
    quickcheck! {
        fn test_fuzzy_md5(pwd: String, salt: String) -> TestResult {
            check_algorithm(pwd, salt, Algorithm::MD5)
        }
    }

    #[cfg(feature = "with_legacy")]
    quickcheck! {
        fn test_fuzzy_unsaltedsha1(pwd: String, salt: String) -> TestResult {
            check_algorithm(pwd, salt, Algorithm::UnsaltedSHA1)
        }
    }

    #[cfg(feature = "with_legacy")]
    quickcheck! {
        fn test_fuzzy_unsaltedmd5(pwd: String, salt: String) -> TestResult {
            check_algorithm(pwd, salt, Algorithm::UnsaltedMD5)
        }
    }

    #[cfg(feature = "with_legacy")]
    quickcheck! {
        fn test_fuzzy_crypt(pwd: String, salt: String) -> TestResult {
            check_algorithm(pwd, salt, Algorithm::Crypt)
        }
    }

}
