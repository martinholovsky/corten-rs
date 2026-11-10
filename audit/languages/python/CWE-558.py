# @compiles: hatch
# CWE-558: libc's getlogin, with its static buffer, is called through ctypes.
import ctypes


def f() -> bytes:
    g = ctypes.CDLL(None).getlogin
    g.restype = ctypes.c_char_p
    return g()
