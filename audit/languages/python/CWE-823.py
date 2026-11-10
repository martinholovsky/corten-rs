# @compiles: hatch
# CWE-823: a base address plus an untrusted offset is read.
import ctypes


def f(base: int, off: int) -> int:
    return ctypes.c_ubyte.from_address(base + off).value
