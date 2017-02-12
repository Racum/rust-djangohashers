extern crate djangohashers;
use djangohashers::*;

fn main() {
    let encoded = make_password("K2jitmJ3CBfo");
    println!("Hash: {:?}", encoded);
    let is_valid = check_password("K2jitmJ3CBfo", &encoded).unwrap();
    println!("Is valid: {:?}", is_valid);
}
