# Change Log

All notable changes to this project will be documented in this file.
This project adheres to [Semantic Versioning](http://semver.org/).

## [0.3.1] - 2018-06-23

### Changed

- Removed deprecated `rand::Rng::gen_ascii_chars()`.
- Silence deprecation warning on `pwhash::unix_crypt`.
- Updated dependencies.

## [0.3.0] - 2017-12-05

### Added

- New compiling features to select that hashers to include.

### Changed

- Renamed Django version enum and its items.

## [0.2.12] - 2017-12-03

### Changed

- Set default Django version to 2.0
- Updated dependencies.

## [0.2.11] - 2017-10-02

### Added

- Added protection against time-attacks on string comparisons.

## [0.2.10] - 2017-09-02

### Added

- Travis-CI badge.

## [0.2.9] - 2017-06-14

### Changed

- Updated base64 to take advantage of new optimizations.

## [0.2.8] - 2017-06-07

### Changed

- Replaced deprecated rustc-serialize with base64.

## [0.2.7] - 2017-04-05

### Changed

- Set default Django version to 1.11.
- Updated dependencies.

## [0.2.6] - 2017-02-04

### Added

- Support to Argon2PasswordHasher.
- Support to Django 1.11.

### Changed

- Set default Django version to 1.10.
- Updated dependencies.

## [0.2.5] - 2016-09-19

### Added

- Fuzzy tests, via quickcheck (thank's @fbecart).

### Changed

- Fixed MD5 check: "blank salt" doesn't mean "unsalted".
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
