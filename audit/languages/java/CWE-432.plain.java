// @rejected: cannot find symbol
// CWE-432: the standard Java API has no signal handler; Signal is only in jdk.unsupported.
class P {
    static void f() {
        Signal.handle(null, null);
    }
}
