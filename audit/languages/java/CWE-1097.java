// @compiles
// CWE-1097: equals is not overridden, so == and equals compare identity for a stored record.
class P {
    static class Rec {
        int id;
    }

    static boolean same(Rec a, Rec b) {
        return a.equals(b);
    }
}
