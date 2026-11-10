// @compiles
// CWE-580: clone() builds a new object instead of calling super.clone(), so a subclass's clone returns the wrong type.
class P {
    static class Account implements Cloneable {
        int owner;
        @Override
        public Account clone() {
            Account a = new Account();
            a.owner = owner;
            return a;
        }
    }
}
