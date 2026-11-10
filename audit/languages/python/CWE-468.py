# @compiles: hatch
# CWE-468: an index is scaled twice: by hand, and by the element size again.
import ctypes


def f(a, i: int) -> int:
    return ctypes.c_int.from_address(ctypes.addressof(a) + i * 4 * 4).value
