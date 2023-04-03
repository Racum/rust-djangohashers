# Rust DjangoHashers

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
Hash: "pbkdf2_sha256$390000$7HRd1YJBZvYj$Rc3BW6f7ss3CShWkULiXI9Rxj7CDdstBeoyCgFFQaK0="
Is valid: true
```


## Installation

Add the dependency to your `Cargo.toml`:

```toml
[dependencies]
djangohashers = "^1.6"
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

By default all the hashers are enabled, but you can pick only the hashers that you need to avoid unneeded dependencies.

* `default`: all hashers.
* `with_pbkdf2`: only **PBKDF2** and **PBKDF2SHA1**.
* `with_argon2`: only **Argon2**.
* `with_scrypt`: only **Scrypt**.
* `with_bcrypt`: only **BCrypt** and **BCryptSHA256**.
* `with_legacy`: only **SHA1**, **MD5**, **UnsaltedSHA1**, **UnsaltedMD5** and **Crypt**.
* `fpbkdf2`: enables **Fast PBKDF2** (requires OpenSSL, see below).
* `fuzzy_tests`: only for development, enables fuzzy tests.

## Fast PBKDF2 Version

Depending on your platform, OS and version of libraries, it is possible that DjangoHashers can be slower than Python/Django's reference implementation. If performance is critical for your case, there is an [alternatice implementation](https://www.cryptologie.net/article/281/pbkdf2-performance-matters/): the package [fastpbkdf2](https://github.com/ctz/rust-fastpbkdf2) uses a C-binding of a [library](https://github.com/ctz/fastpbkdf2) that requires OpenSSL. If **ring**'s implementation of PBKDF2 reaches this level of optiomization, the **fastpbkdf2** version will be deprecated.

### Installation

Add the dependency to your `Cargo.toml` declaring the feature:

```toml
[dependencies.djangohashers]
version = "^1.6"
features = ["fpbkdf2"]
```

You need to install OpenSSL and set the environment variable to make it visible to the compiler; this changes depending on the operation system and package manager, for example, in macOS you may need to do something like this:

```
$ brew install openssl
$ export LIBRARY_PATH="$(brew --prefix openssl)/lib"
$ export CFLAGS="-I$(brew --prefix openssl)/include"
$ cargo ...
```

For other OSs and package managers, [follow the guide](https://cryptography.io/en/latest/installation/) of how to install Python’s **Cryptography** dependencies, that also links against OpenSSL.

### Performance

On a Quad-Core Intel Core i7:

Method  | Encode or Check | Performance
------- | --------------- | -------
Django 4.1.5 on Python 3.11.1 | 189ms | 100% (baseline)
djangohashers with ring::pbkdf2 (default) | 145ms | 76.7% 🐇
djangohashers with fastpbkdf2 | 119ms | 62.9 🐇

On a Apple M1:

Method  | Encode or Check | Performance
------- | --------------- | -------
Django 4.1.5 on Python 3.11.1 | 65ms | 100% (baseline)
djangohashers with ring::pbkdf2 (default) | 38ms | 58.5% 🐇
djangohashers with fastpbkdf2 | 26ms | 40.0% 🐇

Replicate test above with Docker:

```
$ docker build -t rs-dj-hashers-profile .
...

$ docker run -t rs-dj-hashers-profile
Hashing time: 65ms (Python 3.11.1, Django 4.1.5).
Hashing time: 38ms (Vanilla PBKDF2).
Hashing time: 26ms (Fast PBKDF2).
```

## Compatibility

DjangoHashers passes all relevant unit tests from Django 1.4 to 4.2 (and beta of 5.0), there is even a [line-by-line translation](https://github.com/Racum/rust-djangohashers/blob/master/tests/django.rs) of [tests/auth_tests/test_hashers.py](https://github.com/django/django/blob/e403f22/tests/auth_tests/test_hashers.py).

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
* `HasherError::BadHash`: Hash string is corrupted.
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
* `Algorithm::Scrypt`
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

* `DjangoVersion::CURRENT` Current Django version (`4.2` for DjangoHashers `1.6.4`).
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
* `DjangoVersion::V3_0` Django 3.0
* `DjangoVersion::V3_1` Django 3.1
* `DjangoVersion::V3_2` Django 3.2
* `DjangoVersion::V4_0` Django 4.0
* `DjangoVersion::V4_1` Django 4.1
* `DjangoVersion::V4_2` Django 4.2
* `DjangoVersion::V5_0` Django 5.0

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
