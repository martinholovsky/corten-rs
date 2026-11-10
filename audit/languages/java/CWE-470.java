// @compiles
// CWE-470: input names the class that is instantiated.
class P {
    static Object make(String name) throws ReflectiveOperationException {
        return Class.forName(name).getDeclaredConstructor().newInstance();
    }
}
