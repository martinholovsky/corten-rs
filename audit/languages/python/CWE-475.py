# @compiles: hatch
# CWE-475: string_at is given an address that is not valid memory.
import ctypes


def f(addr: int) -> bytes:
    return ctypes.string_at(addr, 4)
