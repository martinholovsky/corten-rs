//@ expect: -F unsafe-code
// CWE-1096: lazily creates a shared instance with no synchronisation.
struct Config {
    level: u32,
}
static mut CONFIG: Option<Config> = None;
fn config_level() -> u32 {
    unsafe {
        if (*(&raw const CONFIG)).is_none() {
            CONFIG = Some(Config { level: 3 });
        }
        match &*(&raw const CONFIG) {
            Some(c) => c.level,
            None => 0,
        }
    }
}
fn main() {
    let handle = std::thread::spawn(config_level);
    println!("{} {:?}", config_level(), handle.join());
}
