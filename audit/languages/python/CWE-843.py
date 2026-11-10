# @compiles: hatch
# CWE-843: a float's bytes are read back as an int through a ctypes cast.
import ctypes


def f(x: float) -> int:
    d = ctypes.c_double(x)
    return ctypes.cast(ctypes.pointer(d), ctypes.POINTER(ctypes.c_long)).contents.value
