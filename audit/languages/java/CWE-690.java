// @compiles
// CWE-690: a method that can return null is dereferenced unchecked.
import java.util.Map;

class P {
    static int f(Map<String, String> m) {
        return m.get("user").length();
    }
}
