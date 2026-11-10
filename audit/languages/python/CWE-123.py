# @compiles: hatch
# CWE-123: a caller-supplied address is written with a caller-supplied value.
import ctypes


def f(where: int, what: int):
    ctypes.c_int.from_address(where).value = what
