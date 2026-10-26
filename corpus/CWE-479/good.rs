use std::sync::mpsc;
// Matched benign program: a shutdown request arrives as a message.
fn main() {
    let (tx, rx) = mpsc::channel::<&str>();
    if let Err(e) = tx.send("shutdown") {
        println!("{e}");
    }
    println!("{:?}", rx.recv());
}
