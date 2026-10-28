//@ fake-dep: my-task-runtime
//@ expect: not on the operator's dependency allowlist
// CWE-396 dependency variant (2026-10-27): an async runtime whose join
// handle returns a task's panic as an error value (a catch-all handler).
// The checker bans `JoinHandle::join` in std, not a dependency's equivalent;
// the stub stands in for the crate. Not detected unless the dependency
// policy refuses it.
fn main() {
    my_task_runtime::stub();
}
