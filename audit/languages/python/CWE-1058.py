# @compiles
# CWE-1058: a function called from threads modifies a module global.
calls = 0


def handle() -> int:
    global calls
    calls += 1
    return calls
