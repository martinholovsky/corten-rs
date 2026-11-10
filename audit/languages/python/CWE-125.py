# @compiles: hatch
# CWE-125: a ctypes array is read at an unchecked offset.
import ctypes


def f(i: int) -> int:
    a = (ctypes.c_int * 4)()
    return ctypes.c_int.from_address(ctypes.addressof(a) + 4 * i).value
