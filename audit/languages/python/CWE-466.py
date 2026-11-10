# @compiles: hatch
# CWE-466: a function returns an address beyond the buffer it came from.
import ctypes


def f(buf) -> int:
    return ctypes.addressof(buf) + ctypes.sizeof(buf) + 16
