#[macro_use]
extern crate djangohashers;

// Django 1.9:
// https://github.com/django/django/blob/e403f22/tests/auth_tests/test_hashers.py

#[cfg(test)]
mod tests {

    use djangohashers::*;

    #[test]
    fn test_simple() {
        let encoded = make_password("lètmein");
        assert!(encoded.starts_with("pbkdf2_sha256$"));
        assert!(is_password_usable(&encoded));
        assert!(check_password("lètmein", &encoded).unwrap());
        assert!(!check_password("lètmeinz", &encoded).unwrap());
        // Blank passwords
        let blank_encoded = make_password("");
        assert!(blank_encoded.starts_with("pbkdf2_sha256$"));
        assert!(is_password_usable(&blank_encoded));
        assert!(check_password("", &blank_encoded).unwrap());
        assert!(!check_password(" ", &blank_encoded).unwrap());
    }

    #[test]
    fn test_pbkdf2() {
        let encoded = make_password_with_settings("lètmein", "seasalt", Algorithm::PBKDF2);
        assert!(encoded ==
                "pbkdf2_sha256$24000$seasalt$V9DfCAVoweeLwxC/L2mb+7swhzF0XYdyQMqmusZqiTc="
                    .to_string());
        assert!(is_password_usable(&encoded));
        assert!(check_password("lètmein", &encoded).unwrap());
        assert!(!check_password("lètmeinz", &encoded).unwrap());
        // Blank passwords
        let blank_encoded = make_password_with_settings("", "seasalt", Algorithm::PBKDF2);
        assert!(blank_encoded.starts_with("pbkdf2_sha256$"));
        assert!(is_password_usable(&blank_encoded));
        assert!(check_password("", &blank_encoded).unwrap());
        assert!(!check_password(" ", &blank_encoded).unwrap());
    }

    #[test]
    fn test_sha1() {
        let encoded = make_password_with_settings("lètmein", "seasalt", Algorithm::SHA1);
        assert!(encoded == "sha1$seasalt$cff36ea83f5706ce9aa7454e63e431fc726b2dc8".to_string());
        assert!(is_password_usable(&encoded));
        assert!(check_password("lètmein", &encoded).unwrap());
        assert!(!check_password("lètmeinz", &encoded).unwrap());
        // Blank passwords
        let blank_encoded = make_password_with_settings("", "seasalt", Algorithm::SHA1);
        assert!(blank_encoded.starts_with("sha1$"));
        assert!(is_password_usable(&blank_encoded));
        assert!(check_password("", &blank_encoded).unwrap());
        assert!(!check_password(" ", &blank_encoded).unwrap());
    }

    #[test]
    fn test_md5() {
        let encoded = make_password_with_settings("lètmein", "seasalt", Algorithm::MD5);
        assert!(encoded == "md5$seasalt$3f86d0d3d465b7b458c231bf3555c0e3".to_string());
        assert!(is_password_usable(&encoded));
        assert!(check_password("lètmein", &encoded).unwrap());
        assert!(!check_password("lètmeinz", &encoded).unwrap());
        // Blank passwords
        let blank_encoded = make_password_with_settings("", "seasalt", Algorithm::MD5);
        assert!(blank_encoded.starts_with("md5$"));
        assert!(is_password_usable(&blank_encoded));
        assert!(check_password("", &blank_encoded).unwrap());
        assert!(!check_password(" ", &blank_encoded).unwrap());
    }

    #[test]
    fn test_unsalted_md5() {
        let encoded = make_password_with_settings("lètmein", "", Algorithm::UnsaltedMD5);
        assert!(encoded == "88a434c88cca4e900f7874cd98123f43".to_string());
        assert!(check_password("lètmein", &encoded).unwrap());
        assert!(!check_password("lètmeinz", &encoded).unwrap());
        // Blank passwords
        let blank_encoded = make_password_with_settings("", "", Algorithm::UnsaltedMD5);
        assert!(check_password("", &blank_encoded).unwrap());
        assert!(!check_password(" ", &blank_encoded).unwrap());
    }

    #[test]
    fn test_unsalted_sha1() {
        let encoded = make_password_with_settings("lètmein", "", Algorithm::UnsaltedSHA1);
        assert!(encoded == "sha1$$6d138ca3ae545631b3abd71a4f076ce759c5700b".to_string());
        assert!(is_password_usable(&encoded));
        assert!(check_password("lètmein", &encoded).unwrap());
        assert!(!check_password("lètmeinz", &encoded).unwrap());
        // Blank passwords
        assert!(!check_password("lètmein", "6d138ca3ae545631b3abd71a4f076ce759c5700b").unwrap());
        let blank_encoded = make_password_with_settings("", "", Algorithm::UnsaltedSHA1);
        assert!(blank_encoded.starts_with("sha1$"));
        assert!(is_password_usable(&blank_encoded));
        assert!(check_password("", &blank_encoded).unwrap());
        assert!(!check_password(" ", &blank_encoded).unwrap());
    }

}
