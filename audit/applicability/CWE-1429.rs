//@ compiles: safe
// CWE-1429, missing security-relevant feedback for unexecuted operations
// in a hardware interface: the MITRE interrupt-handler example in safe
// Rust. A lower-priority interrupt is dropped with no counter, log or error.
pub struct Controller { pub priority: [u8; 32], pub current: u8 }
fn process_interrupt(_irq: usize) {}
pub fn interrupt_handler(c: &Controller, irq: usize) {
    if c.priority[irq] < c.current {
        return;
    }
    process_interrupt(irq);
}
