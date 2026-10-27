//@ compiles: safe
// CWE-374, passing a mutable object to an untrusted method. The allow-list is
// handed over as &mut rather than as a clone, so the plugin can rewrite it.
// (Passing &Vec instead would make the borrow checker reject any mutation.)
pub trait Plugin {
    fn inspect(&self, allowed: &mut Vec<String>);
}
pub fn run(plugin: &dyn Plugin, allowed: &mut Vec<String>) {
    plugin.inspect(allowed);
}
