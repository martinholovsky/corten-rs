//! `corten-driver`: rustc with Corten's custom lints registered.
#![feature(rustc_private, default_field_values)]
#![forbid(unsafe_code)]

extern crate rustc_driver;
extern crate rustc_errors;
extern crate rustc_hir;
extern crate rustc_interface;
extern crate rustc_lint;
extern crate rustc_middle;
extern crate rustc_session;
extern crate rustc_span;

mod lints;

struct Callbacks;

impl rustc_driver::Callbacks for Callbacks {
    fn config(&mut self, config: &mut rustc_interface::interface::Config) {
        config.register_lints = Some(Box::new(|_sess, store| lints::register(store)));
    }
}

fn main() {
    let mut args: Vec<String> = std::env::args().collect();
    // As RUSTC_WRAPPER, cargo passes the rustc path first.
    if args
        .get(1)
        .and_then(|a| std::path::Path::new(a).file_stem())
        .is_some_and(|s| s == "rustc")
    {
        args.remove(1);
    }
    rustc_driver::compiler_entrypoint(&args, &mut Callbacks);
}
