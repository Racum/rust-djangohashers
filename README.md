# Rust DjangoHashers

A Rust port of the password primitives used in Django project.

Django's `django.contrib.auth.models.User` class has a few methods to deal with password, like `set_password()` and `check_password()`; **DjangoHashers** implements the primitive functions behind that methods.

All built-in hashers (except UNIX's `crypt(3)`) are supported:

* PBKDF2
* PBKDF2SHA1
* BCryptSHA256
* BCrypt
* SHA1
* MD5
* UnsaltedSHA1
* UnsaltedMD5

## Instalation

Add the dependency to your `Cargo.toml`:

```toml
[dependencies]
djangohashers = "0.1.0"
```

Reference the crate in your code:

```rust
extern crate djangohashers;
use djangohashers::*;

...
```

## Compatibility

DjangoHashers passes all relevant unit tests from Django 1.9, there is even a [line-by-line translation](https://github.com/Racum/rust-djangohashers/blob/master/tests/django.rs) of [tests/auth_tests/test_hashers.py](https://github.com/django/django/blob/e403f22/tests/auth_tests/test_hashers.py).

What is **not** covered:

* `CryptPasswordHasher`, that uses UNIX's `crypt(3)` hash function.
* Upgrade/Downgrade callbacks (`must_update`, `setter`).
* Any 3rd-party hasher outside Django's code.
* Some tests that makes no sense in idiomatic Rust.

## Usage

### Verifying a Hashed Password

Function signature:

```rust
pub fn check_password(password: &str, encoded: &str) -> Result<bool, HasherError> {...}
```

Example:

```rust
let password = "KRONOS"; // Sent by the user.
let encoded = "pbkdf2_sha256$24000$..."; // Fetched from DB.

match check_password(password, encoded) {
    Ok(valid) => {
        if valid {
            // Log the user in.
        } else {
            // Ask the user to try again.
        }
    }
    Err(error) => {
        // Deal with the error.
    }
}
```

### Generating a Hashed Password

Function signatures:

```rust
pub fn make_password(password: &str) -> String {...}
pub fn make_password_with_algorithm(password: &str, algorithm: Algorithm) -> String {...}
pub fn make_password_with_settings(password: &str, salt: &str, algorithm: Algorithm) -> String {...}
```

Using default settings (PBKDF2 algorithm, random salt):

```rust
let encoded = make_password("KRONOS");
// Returns something like:
// pbkdf2_sha256$24000$go9s3b1y1BTe$Pksk4EptJ84KDnI7ciocmhzFAb5lFoFwd6qlPOwwW4Q=
```

Using a defined algorithm (random salt):

```rust
let encoded = make_password_with_algorithm("KRONOS", Algorithm::BCryptSHA256);
// Returns something like:
// bcrypt_sha256$$2b$12$e5C3zfswn.CowOBbbb7ngeYbxKzJePCDHwo8AMr/SZeZCoGrk7oue
```

Using a defined algorithm and salt:

```rust
let encoded = make_password_with_settings("KRONOS", "seasalt", Algorithm::PBKDF2SHA1);
// Returns exactly this (remember, the salt is fixed!):
// pbkdf2_sha1$24000$seasalt$F+kiWNHXbMBcwgxsvSKFCWHnZZ0=
```

### Utilities

Function signature:

```rust
pub fn is_password_usable(encoded: &str) -> bool {...}
```

You can check if the password hash is properly formatted before running the expensive cryto stuff:

```rust
let encoded = "pbkdf2_sha256$24000$..."; // Fetched from DB.

if is_password_usable(encoded) {
    // Go ahead.
} else {
    // Check your database or report an issue.
}
```

## License

Rust DjangoHashers is released under the **3-Clause BSD License**.
