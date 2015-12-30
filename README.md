# Rust DjangoHashers

A Rust port of the password primitives used in Django project.

Django's `django.contrib.auth.models.User` class has a few methods to deal with password, like `set_password()` and `check_password()`; **DjangoHashers** implements the primitive functions behind that methods.

All built-in hashers (with the exception of UNIX's `crypt(3)`) are supported:

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


## Usage

### Verifying a Hashed Password

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

TODO

## License

Rust DjangoHashers is released under the **3-Clause BSD License**.
