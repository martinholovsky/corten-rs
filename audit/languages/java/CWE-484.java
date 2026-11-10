// @compiles
// CWE-484: the admin case falls through into the user case.
class P {
    static int f(int role) {
        int level = 0;
        switch (role) {
        case 1:
            level = 2;
        case 2:
            level = 1;
            break;
        }
        return level;
    }
}
