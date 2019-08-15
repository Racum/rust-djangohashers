use djangohashers::*;

#[test]
#[cfg(feature = "with_pbkdf2")]
fn test_pbkdf2_deny_of_servicez() {
    let encoded = format!("pbkdf2_sha256${}$salt$hash", std::u32::MAX);
    assert_eq!(
        check_password("pass", &encoded),
        Err(HasherError::InvalidIterations)
    );
}

#[test]
#[cfg(feature = "with_pbkdf2")]
fn test_pbkdf2_sha1_deny_of_service() {
    let encoded = format!("pbkdf2_sha1${}$salt$hash", std::u32::MAX);
    assert_eq!(
        check_password("pass", &encoded),
        Err(HasherError::InvalidIterations)
    );
}

#[test]
#[cfg(feature = "with_bcrypt")]
fn test_bcrypt_deny_of_service() {
    let encoded = format!("bcrypt$$2b${}$hash", 17);
    assert_eq!(
        check_password("pass", &encoded),
        Err(HasherError::InvalidIterations)
    );
}

#[test]
#[cfg(feature = "with_bcrypt")]
fn test_bcrypt_sha256_deny_of_service() {
    let encoded = format!("bcrypt_sha256$$2b${}$hash", 17);
    assert_eq!(
        check_password("pass", &encoded),
        Err(HasherError::InvalidIterations)
    );
}
