use djangohashers::make_password;
use std::time::Instant;

fn main() {
    let now = Instant::now();
    for _ in 0..100 {
        let _ = make_password("lètmein");
    }

    #[cfg(feature = "fpbkdf2")]
    println!(
        "Hashing time: {}ms (Fast PBKDF2).",
        now.elapsed().as_millis() / 100
    );

    #[cfg(not(feature = "fpbkdf2"))]
    println!(
        "Hashing time: {}ms (Vanilla PBKDF2).",
        now.elapsed().as_millis() / 100
    );
}
