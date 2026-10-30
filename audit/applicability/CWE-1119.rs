//@ compiles: safe
// CWE-1119, excessive unconditional branching: labeled break/continue used
// as gotos throughout; rustc sets no limit.
pub fn scan(rows: &[Vec<u8>]) -> Option<(usize, usize)> {
    let mut hit = None;
    'rows: for (i, r) in rows.iter().enumerate() {
        'cols: for (j, &c) in r.iter().enumerate() {
            if c == 0 {
                continue 'rows;
            }
            if c == 1 {
                continue 'cols;
            }
            if c == 2 {
                hit = Some((i, j));
                break 'rows;
            }
            if c == 3 {
                break 'cols;
            }
        }
    }
    hit
}
