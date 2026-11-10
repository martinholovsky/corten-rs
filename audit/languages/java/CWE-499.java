// @compiles
// CWE-499: a Serializable class serialises its password field.
import java.io.Serializable;

class P {
    static class Session implements Serializable {
        String user;
        String password;
    }
}
