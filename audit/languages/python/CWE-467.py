# @compiles: hatch
# CWE-467: ctypes.sizeof of a pointer gives the pointer's size, not the buffer's.
import ctypes


def f(key: ctypes.POINTER(ctypes.c_char)) -> int:
    return ctypes.sizeof(key)
