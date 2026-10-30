//@ compiles: safe
// CWE-486, comparison of classes by name. std::any::type_name is safe and
// its docs say the string "must not be considered to be a unique
// identifier of a type"; two crates can both have a `Plugin` type. Using
// it as a trust decision is the weakness. TypeId would be the fix.
pub fn is_trusted_plugin<T: ?Sized>() -> bool {
    std::any::type_name::<T>().ends_with("::Plugin")
}
