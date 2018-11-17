# Rust DjangoHashers

[![Build Status](https://travis-ci.org/Racum/rust-djangohashers.svg?branch=master)](https://travis-ci.org/Racum/rust-djangohashers)

A Rust port of the password primitives used in [Django Project](https://www.djangoproject.com).

Django's `django.contrib.auth.models.User` class has a few methods to deal with passwords, like `set_password()` and `check_password()`; **DjangoHashers** implements the primitive functions behind those methods. All Django's built-in hashers are supported.

This library was conceived for Django integration, but is not limited to it; you can use the password hash algorithm in any Rust project (or FFI integration), since its security model is already battle-tested.

## TL;DR

Content of `examples/tldr.rs`:

```rust
extern crate djangohashers;
use djangohashers::*;

fn main() {
    let encoded = make_password("K2jitmJ3CBfo");
    println!("Hash: {:?}", encoded);
    let is_valid = check_password("K2jitmJ3CBfo", &encoded).unwrap();
    println!("Is valid: {:?}", is_valid);
}
```

Output:

```
$ cargo run --quiet --example tldr
Hash: "pbkdf2_sha256$30000$E2DtC4weM2DY$ZTso63dGXbq+QdVGUwq8Y05RgyUc3AsUSfswqUOZ3xc="
Is valid: true
```


## Installation

Add the dependency to your `Cargo.toml`:

```toml
[dependencies]
djangohashers = "^0.3"
```

Reference and import:

```rust
extern crate djangohashers;

// Everything (it's not much):
use djangohashers::*;

// Or, just what you need:
use djangohashers::{check_password, make_password, Algorithm};
```

## Compiling Features

> New in `0.3.0`.

By default all the hashers are enabled, but you can pick only the hashers that you need to avoid unneeded dependencies.

* `default`: all hashers.
* `with_pbkdf2`: only **PBKDF2** and **PBKDF2SHA1**.
* `with_argon2`: only **Argon2**.
* `with_bcrypt`: only **BCrypt** and **BCryptSHA256**.
* `with_legacy`: only **SHA1**, **MD5**, **UnsaltedSHA1**, **UnsaltedMD5** and **Crypt**.
* `fpbkdf2`: enables **Fast PBKDF2** (requires OpenSSL, see below).
* `fuzzy_tests`: only for development, enables fuzzy tests.

## Fast PBKDF2 Version

Unfortunately rust-crypto’s implementation of PBKDF2 is not properly optimized: it does not adhere to the loop inlines and buffering used in [modern implementations](https://jbp.io/2015/08/11/pbkdf2-performance-matters/). The package [fastpbkdf2](https://github.com/ctz/rust-fastpbkdf2) uses a C-binding of a [library](https://github.com/ctz/fastpbkdf2) that requires OpenSSL.

### Installation

Add the dependency to your `Cargo.toml` declaring the feature:

```toml
[dependencies.djangohashers]
version = "^0.3"
features = ["fpbkdf2"]
```

You need to install OpenSSL and set the environment variable to make it visible to the compiler; this changes depending on the operation system and package manager, for example, in macOS you may need to do something like this:

Via [Homebrew](http://brew.sh):

```
$ brew install openssl
$ CFLAGS="-I/usr/local/opt/openssl/include" cargo ...
```

Via [MacPorts](https://www.macports.org):

```
$ sudo port install openssl
$ CFLAGS="-I/opt/local/include" cargo ...
```

For other OSs and package managers, [follow the guide](https://cryptography.io/en/latest/installation/) of how to install Python’s **Cryptography** dependencies, that also links against OpenSSL.

### Performance

Method  | Encode or Check | Performance
------- | --------------- | -------
Django 1.9.4 | 29.5ms | Baseline
djangohashers with rust-crypto 0.2.34 (default) | 41.7ms | 41% slower
djangohashers with fastpbkdf2 0.1.0 | 23.1ms | 28% faster

Notes:

* Best of 5 rounds of 100 events.
* Built with `--release`.
* PBKDF2 using SHA256 and iteration count set to 24000.
* Django version tested with CPython 3.5.1
* Rust/fastpbkdf2 version tested with Rust 1.6.0 and OpenSSL 1.0.2g.
* iMac Mid 2010 with an Intel Core i3 3.2Ghz and 16GB of RAM, running OS X 10.11.3.


## Compatibility

DjangoHashers passes all relevant unit tests from Django 1.4 to 2.0, there is even a [line-by-line translation](https://github.com/Racum/rust-djangohashers/blob/master/tests/django.rs) of [tests/auth_tests/test_hashers.py](https://github.com/django/django/blob/e403f22/tests/auth_tests/test_hashers.py).

What is **not** covered:

* Upgrade/Downgrade callbacks.
* Any 3rd-party hasher outside Django's code.
* Some tests that makes no sense in idiomatic Rust.

## Usage

[API Documentation](https://docs.rs/djangohashers/), thanks to **docs.rs** project!

### Verifying a Hashed Password

Function signatures:

```rust
pub fn check_password(password: &str, encoded: &str) -> Result<bool, HasherError> {}
pub fn check_password_tolerant(password: &str, encoded: &str) -> bool {}
```

Complete version:

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

Possible Errors:

* `HasherError::UnknownAlgorithm`: anything not recognizable as an algorithm.
* `HasherError::InvalidIterations`: number of iterations is not a positive integer.
* `HasherError::EmptyHash`: hash string is empty.
* `HasherError::InvalidArgon2Salt`: Argon2 salt should be Base64 encoded.


If you want to automatically assume all errors as *"invalid password"*, there is a shortcut for that:

```rust
if check_password_tolerant(password, encoded) {
	// Log the user in.
} else {
	// Ask the user to try again.
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
* `Algorithm::Argon2`
* `Algorithm::BCryptSHA256`
* `Algorithm::BCrypt`
* `Algorithm::SHA1`
* `Algorithm::MD5`
* `Algorithm::UnsaltedSHA1`
* `Algorithm::UnsaltedMD5`
* `Algorithm::Crypt`

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

**Warning**: `make_password_with_settings` and `make_password_core` will both panic if salt is not only letters and numbers (`^[A-Za-z0-9]*$`).

### Generating a Hashed Password based on a Django version

> New in `0.2.1`.

Django versions can have different number of iterations for hashers based on PBKDF2 and BCrypt algorithms; this abstraction makes possible to generate a password with the same number of iterations used in that versions.

```rust
use djangohashers::{Django, DjangoVersion};

let django = Django {version: DjangoVersion::V1_8};  // Django 1.8.
let encoded = django.make_password("KRONOS");
// Returns something like:
// pbkdf2_sha256$20000$u0C1E8jrnAYx$7KIo/fAuBJpswQyL7pTxO06ccrSjGdIe7iSqzdVub1w=
//               |||||
// ...notice the 20000 iterations, used in Django 1.8.
```

Available versions:

* `DjangoVersion::Current` Current Django version (`2.1` for DjangoHashers `0.3.2`).
* `DjangoVersion::V1_4` Django 1.4
* `DjangoVersion::V1_5` Django 1.5
* `DjangoVersion::V1_6` Django 1.6
* `DjangoVersion::V1_7` Django 1.7
* `DjangoVersion::V1_8` Django 1.8
* `DjangoVersion::V1_9` Django 1.9
* `DjangoVersion::V1_10` Django 1.10
* `DjangoVersion::V1_11` Django 1.11
* `DjangoVersion::V2_0` Django 2.0
* `DjangoVersion::V2_1` Django 2.1
* `DjangoVersion::V2_2` Django 2.2

### Verifying a Hash Format (pre-crypto)

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
