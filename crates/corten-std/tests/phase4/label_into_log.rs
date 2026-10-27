//@ expect: the trait bound `Labeled<&str, corten_std::label::Secret>: ToString` is not satisfied
use corten_std::label::{Labeled, Secret};
fn main() {
    let token: Labeled<&str, Secret> = Labeled::new("s3cr3t");
    let record = corten_std::log_record!("auth.ok", token = token);
    println!("{}", record.render());
}
