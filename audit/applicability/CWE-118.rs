//@ compiles: safe
// CWE-118, incorrect access of an indexable resource. Many 16-byte user
// records share one buffer; the bounds check is against the allocation, not
// the record, so an unchecked offset >= 16 reads the next user's record.
pub struct Table {
    pub data: Vec<u8>,
}
pub fn field(t: &Table, record: usize, offset: usize) -> u8 {
    t.data[record * 16 + offset]
}
