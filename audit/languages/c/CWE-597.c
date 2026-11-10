// @compiles
// CWE-597: == compares the two pointers, not the strings.
int is_admin(const char *role) {
    return role == "admin";
}
