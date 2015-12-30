# Rust DjangoHashers

A Rust port of the password primitives used in Django project.

Django's `django.contrib.auth.models.User` class has a few methods to deal with passwords, like `set_password()` and `check_password()`; **DjangoHashers** implements the primitive functions behind that methods. All Django's built-in hashers (except UNIX's `crypt(3)`) are supported.

This library was conceived for Django integration, but is not limited to it; you can use the password hash algorithm in any Rust project (or FFI integration), since its security model is already battle-tested.

## Instalation

Add the dependency to your `Cargo.toml`:

```toml
[dependencies]
djangohashers = "0.1.0"
```

Reference and import:

```rust
extern crate djangohashers;

// Everything (it's not much):
use djangohashers::*;

// Or, just what you need:
use djangohashers::{check_password, make_password, Algorithm}

...
```

## Compatibility

DjangoHashers passes all relevant unit tests from Django 1.9, there is even a [line-by-line translation](https://github.com/Racum/rust-djangohashers/blob/master/tests/django.rs) of [tests/auth_tests/test_hashers.py](https://github.com/django/django/blob/e403f22/tests/auth_tests/test_hashers.py).

What is **not** covered:

* `CryptPasswordHasher`, that uses UNIX's `crypt(3)` hash function.
* Upgrade/Downgrade callbacks.
* Any 3rd-party hasher outside Django's code.
* Some tests that makes no sense in idiomatic Rust.

## Usage

### Verifying a Hashed Password

Function signature:

```rust
pub fn check_password(password: &str, encoded: &str) -> Result<bool, HasherError> {}
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
pub fn make_password(password: &str) -> String {}
pub fn make_password_with_algorithm(password: &str, algorithm: Algorithm) -> String {}
pub fn make_password_with_settings(password: &str, salt: &str, algorithm: Algorithm) -> String {}
```

Available algorithms:

* `Algorithm::PBKDF2` (default)
* `Algorithm::PBKDF2SHA1`
* `Algorithm::BCryptSHA256`
* `Algorithm::BCrypt`
* `Algorithm::SHA1`
* `Algorithm::MD5`
* `Algorithm::UnsaltedSHA1`
* `Algorithm::UnsaltedMD5`

The algorithms follow the same Django naming model, minus the `PasswordHasher` suffix.

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

Using a defined algorithm and salt (not recommended, use it only for debug):

```rust
let encoded = make_password_with_settings("KRONOS", "seasalt", Algorithm::PBKDF2SHA1);
// Returns exactly this (remember, the salt is fixed!):
// pbkdf2_sha1$24000$seasalt$F+kiWNHXbMBcwgxsvSKFCWHnZZ0=
```

### Utilities

Function signature:

```rust
pub fn is_password_usable(encoded: &str) -> bool {}
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

## Contributing

* Be patient with me, I’m new to Rust and this is my first project.
* Don't go nuts with your *mad-rust-skillz*, legibility is a priority.
* Please use [rustfmt](https://github.com/rust-lang-nursery/rustfmt) in your code.
* Always include some test case.

## License

Rust DjangoHashers is released under the **3-Clause BSD License**.

**tl;dr**: *"free to use as long as you credit me"*.
