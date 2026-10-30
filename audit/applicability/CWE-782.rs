//@ compiles: safe
// CWE-782, IOCTL without access control. The driver's dispatch (stubbed: the
// register file is an array) writes a privileged register for any caller,
// never checking the caller's credentials.
pub struct Caller {
    pub uid: u32,
}
pub fn ioctl(_caller: &Caller, cmd: u32, arg: u64, regs: &mut [u64; 4]) -> i32 {
    match cmd {
        0x10 => {
            regs[0] = arg;
            0
        }
        _ => -22,
    }
}
