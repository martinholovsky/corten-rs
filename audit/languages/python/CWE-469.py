# @compiles: hatch
# CWE-469: addresses of two different buffers are subtracted for a length.
import ctypes


def f(a, b) -> int:
    return ctypes.addressof(b) - ctypes.addressof(a)
