#[macro_use] extern crate quickcheck;
extern crate djangohashers;

#[cfg(feature = "fuzzy_tests")]
mod fuzzy_tests {
    use djangohashers::*;
    use quickcheck::TestResult;
    extern crate base64;

    use self::base64::{encode_config, URL_SAFE_NO_PAD};

    fn check_algorithm(pwd: String, salt: String, algorithm: Algorithm) -> TestResult {
        if !VALID_SALT_RE.is_match(&salt) {
            return TestResult::discard();
        }

        TestResult::from_bool(check_password_tolerant(&pwd, &make_password_with_settings(&pwd, &salt, algorithm)))
    }

    quickcheck! {
        fn test_fuzzy_pbkdf2(pwd: String, salt: String) -> TestResult {
            check_algorithm(pwd, salt, Algorithm::PBKDF2)
        }
    }

    quickcheck! {
        fn test_fuzzy_pbkdf2sha1(pwd: String, salt: String) -> TestResult {
            check_algorithm(pwd, salt, Algorithm::PBKDF2SHA1)
        }
    }

    quickcheck! {
        fn test_fuzzy_argon2(pwd: String, salt: String) -> TestResult {
            check_algorithm(pwd, encode_config(salt.as_bytes(), URL_SAFE_NO_PAD), Algorithm::Argon2)
        }
    }

    quickcheck! {
        fn test_fuzzy_bcryptsha256(pwd: String, salt: String) -> TestResult {
            check_algorithm(pwd, salt, Algorithm::BCryptSHA256)
        }
    }

    quickcheck! {
        fn test_fuzzy_bcrypt(pwd: String, salt: String) -> TestResult {
            if pwd.len() >= 72 {
                return TestResult::discard();
            }

            check_algorithm(pwd, salt, Algorithm::BCrypt)
        }
    }

    quickcheck! {
        fn test_fuzzy_sha1(pwd: String, salt: String) -> TestResult {
            check_algorithm(pwd, salt, Algorithm::SHA1)
        }
    }

    quickcheck! {
        fn test_fuzzy_md5(pwd: String, salt: String) -> TestResult {
            check_algorithm(pwd, salt, Algorithm::MD5)
        }
    }

    quickcheck! {
        fn test_fuzzy_unsaltedsha1(pwd: String, salt: String) -> TestResult {
            check_algorithm(pwd, salt, Algorithm::UnsaltedSHA1)
        }
    }

    quickcheck! {
        fn test_fuzzy_unsaltedmd5(pwd: String, salt: String) -> TestResult {
            check_algorithm(pwd, salt, Algorithm::UnsaltedMD5)
        }
    }

    quickcheck! {
        fn test_fuzzy_crypt(pwd: String, salt: String) -> TestResult {
            check_algorithm(pwd, salt, Algorithm::Crypt)
        }
    }
}
