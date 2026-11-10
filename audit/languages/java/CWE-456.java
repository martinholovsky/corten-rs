// @compiles
// CWE-456: a field never assigned is used at its default null.
class P {
    String role;

    boolean isAdmin() {
        return role.equals("admin");
    }
}
