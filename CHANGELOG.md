# Change Log

All notable changes to this project will be documented in this file.
This project adheres to [Semantic Versioning](http://semver.org/).

## [0.2.4] - 2016-09-18

### Changed

- Fixed MD5 check: "blank salt" doesn't mean "unsalted".


## [0.2.3] - 2016-09-18

### Changed

- Function make_password_core now panics with Invalid salt.

## [0.2.2] - 2016-03-29

### Added

- Support to CryptPasswordHasher, UNIX crypt(3) hash function.

## [0.2.1] - 2016-03-24

### Added

- Option of choosing a Django version to generate the password.

## [0.2.0] - 2016-03-22

### Added

- Option of using fastpbkdf2 (requires OpenSSL to build).

## [0.1.0] - 2016-01-01

### Added

- Functional parity with actual password hashers from Django Project.
- Line-by-line translation from Django’s tests.
- Extra tests to guarantee compatibility.
