extern crate djangohashers;
use djangohashers::{check_password, make_password};

fn main() {
    let encoded = make_password("KRONOS");
    if check_password("KRONOS", &encoded).unwrap() {
        println!("Yeap! your password is good!");
    } else {
        println!("Maybe another time...");
    }
}
