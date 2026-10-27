//@ compiles: safe
// CWE-460, improper cleanup on a thrown exception. Rust's `?` (and a panic)
// leave the function before `busy` is reset, so the worker stays marked busy.
pub struct Worker {
    pub busy: bool,
}
impl Worker {
    pub fn run(&mut self, job: &str) -> Result<u32, std::num::ParseIntError> {
        self.busy = true;
        let n: u32 = job.parse()?;
        self.busy = false;
        Ok(n)
    }
}
