# @compiles: hatch
# CWE-170: a buffer without a terminator is read as a C string.
import ctypes


def f() -> bytes:
    buf = (ctypes.c_char * 8)(*b"aaaaaaaa")
    return ctypes.string_at(buf)
