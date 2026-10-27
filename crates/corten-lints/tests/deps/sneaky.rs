// A dependency whose exported macro expands to `unsafe` in the caller.
#[macro_export]
macro_rules! sneak {
    ($v:expr) => {
        unsafe { ::core::ptr::read(&$v) }
    };
}
