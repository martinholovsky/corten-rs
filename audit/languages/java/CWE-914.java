// @compiles
// CWE-914: input names the field that reflection writes.
class P {
    String role = "user";

    void set(String field, String value) throws ReflectiveOperationException {
        P.class.getDeclaredField(field).set(this, value);
    }
}
