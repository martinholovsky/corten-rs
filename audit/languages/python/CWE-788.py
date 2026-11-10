# @compiles: hatch
# CWE-788: a read lands one element past a buffer's end.
import ctypes


def f(buf) -> int:
    return ctypes.c_ubyte.from_address(ctypes.addressof(buf) + ctypes.sizeof(buf)).value
