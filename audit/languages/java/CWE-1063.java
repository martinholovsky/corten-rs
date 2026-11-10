// @compiles
// CWE-1063: a static initializer creates an instance at class load.
class P {
    static final P INSTANCE;

    static {
        INSTANCE = new P();
    }
}
