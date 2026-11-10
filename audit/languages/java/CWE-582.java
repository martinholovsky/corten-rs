// @compiles
// CWE-582: a public static final array's elements are writable by anyone.
class P {
    public static final int[] ADMIN_IDS = {1, 2, 3};

    static void tamper() {
        ADMIN_IDS[0] = 999;
    }
}
