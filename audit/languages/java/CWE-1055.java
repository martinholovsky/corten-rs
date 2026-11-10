// @rejected: '{' expected
// CWE-1055: Java classes extend one class; extending two is rejected.
class P {
    static class A {}
    static class B {}
    static class C extends A, B {}
}
