# Change Log

All notable changes to this project will be documented in this file.
This project adheres to [Semantic Versioning](http://semver.org/).

## [1.7.4] - 2024-10-09

### Added

- Support to Django 5.2.

### Changed

- Set default Django version to 5.1.

## [1.7.3] - 2024-03-12

### Changed

- Updated base64 dependency.

## [1.7.2] - 2023-12-04

### Added

- Support to Django 5.1.

### Changed

- Set default Django version to 5.0.

## [1.7.1] - 2023-10-03

### Changed

- Updated ring dependency.

## [1.7.0] - 2023-08-18

### Changed

- Migrated to Rust Edition 2021.

## [1.6.9] - 2023-08-18

### Changed

- Updated rust-argon2 dependency.

## [1.6.8] - 2023-07-06

### Changed

- Updated bcrypt dependency.

## [1.6.7] - 2023-06-21

### Changed

- Updated constant_time_eq dependency.

## [1.6.6] - 2023-04-22

### Changed

- No changes, just applied clippy fixes.

## [1.6.5] - 2023-04-03

### Changed

- Set default Django version to 4.2.

## [1.6.3] - 2023-03-09

### Changed

- Updated scrypt dependency.

## [1.6.2] - 2023-02-10

### Changed

- Fix README.

## [1.6.1] - 2023-02-08

### Added

- Support to Django 5.0

### Changed

- Updated PBKDF2 iterations to 600000 for Django 4.2.
- Updated bcrypt dependency.

## [1.6.0] - 2023-01-13

### Added

- Support to Django 4.2.

### Changed

- Set default Django version to 4.1.

## [1.5.10] - 2023-01-12

### Changed

- Updated base64 dependency.

## [1.5.9] - 2022-08-21

### Changed

- Compile requirements with opt-level = 1.

## [1.5.8] - 2022-05-29

### Changed

- Updated bcrypt dependency.

## [1.5.7] - 2022-03-20

### Changed

- Updated dependencies.

## [1.5.6] - 2022-02-28

### Changed

- Updated bcrypt dependency.

## [1.5.5] - 2022-02-23

### Changed

- Updated bcrypt dependency.

## [1.5.4] - 2022-02-18

### Changed

- Updated scrypt dependency.

## [1.5.3] - 2022-01-08

### Changed

- Updated rust-argon2 dependency.

## [1.5.2] - 2022-01-05

### Changed

- Argon2 hasher now encodes as Argon2id variant.

## [1.5.1] - 2021-12-07

### Changed

- Fixed PREFERRED_ALGORITHM resolution.

## [1.5.0] - 2021-12-07

### Added

- Support to ScryptHasher (added on Django 4.0).
- Support to Django 4.1.

### Changed

- Set default Django version to 4.0.
- Updated dependencies.

## [1.4.3] - 2021-06-18

### Changed

- Updated bcrypt dependency.

## [1.4.2] - 2021-06-15

### Changed

- Cleaner code (thank's @andy128k).
- Build via GitHub CI (thank's @andy128k).

## [1.4.1] - 2021-04-07

### Changed

- Set default Django version to 3.1.

### Added

- Support to Django 4.0.

## [1.4.0] - 2021-01-10

### Changed

- Changed pbkdf2 crate to ring for PBKDF2 algorithms.
- Updated dependencies.

## [1.3.2] - 2021-01-02

### Changed

- Updated dependencies.
- Fix compatibility with rand 0.8.

## [1.3.1] - 2020-09-13

### Changed

- Set default Django version to 3.1.
- Updated dependencies.

### Added

- Support to Django 3.2.

## [1.3.0] - 2020-06-20

### Changed

- Pure-Rust implementation of Argon2 (cargon -> rust-argon2).
- Updated dependencies.

### Added

- Support for ARM 64-bit CPUs.

## [1.2.1] - 2020-06-06

### Changed

- Updated dependencies.

## [1.2.0] - 2020-02-19

### Added

- Support to Django 3.1.

### Changed

- Cleaner code (thank's @andy128k).
- Set default Django version to 3.0.
- Updated dependencies.

## [1.1.1] - 2019-08-21

### Added

- Speed comparison with Django via Docker.

## [1.1.0] - 2019-08-16

### Added

- Support to Django 3.0.
- Support to Django 2.2.

### Changed

- Protection against Denial-of-Service for high iterations.
- Set default Django version to 2.2.
- Updated dependencies.

## [1.0.1] - 2019-01-27

### Changed

- Ignored null-character password fuzzing for BCrypt (thank's @andy128k).

## [1.0.0] - 2019-01-19

### Changed

- Update to Rust 2018 edition (thank's @andy128k).
- Switch to RustCrypto implementations (thank's @andy128k).
- Added error case for HasherError::BadHash (thank's @andy128k).
- Updated dependencies.

## [0.3.2] - 2018-11-17

### Added

- Support to Django 2.1.
- Support to Django 2.2.

### Changed

- Set default Django version to 2.1.
- Updated dependencies.

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
