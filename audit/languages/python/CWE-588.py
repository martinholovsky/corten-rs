# @compiles: hatch
# CWE-588: an int is read as a two-field structure.
import ctypes


class Hdr(ctypes.Structure):
    _fields_ = [("n", ctypes.c_int), ("typ", ctypes.c_int)]


def f() -> int:
    x = ctypes.c_int(1)
    return ctypes.cast(ctypes.pointer(x), ctypes.POINTER(Hdr)).contents.typ
