//@ deps: corten-std
use std::sync::OnceLock;
struct Config {
    level: u32,
}
fn config() -> &'static Config {
    static CONFIG: OnceLock<Config> = OnceLock::new();
    CONFIG.get_or_init(|| Config { level: 3 })
}
fn main() {
    let handle = corten_std::thread::spawn(|| config().level);
    println!("{} {:?}", config().level, handle.join());
}
