//@ compiles: safe
// CWE-766, critical data declared public: any code can set is_admin.
pub struct Session {
    pub user: String,
    pub is_admin: bool,
}
