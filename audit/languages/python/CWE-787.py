# @compiles: hatch
# CWE-787: an array is written at an unchecked offset.
import ctypes


def f(i: int, v: int):
    a = (ctypes.c_int * 8)()
    ctypes.c_int.from_address(ctypes.addressof(a) + 4 * i).value = v
