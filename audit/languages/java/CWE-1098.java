// @compiles
// CWE-1098: clone() copies the array reference, so both objects share it.
class P {
    static class Buf implements Cloneable {
        byte[] data = new byte[8];
        @Override
        public Buf clone() throws CloneNotSupportedException {
            return (Buf) super.clone();
        }
    }
}
