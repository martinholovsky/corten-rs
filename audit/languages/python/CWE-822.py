# @compiles: hatch
# CWE-822: an address taken from a message is dereferenced.
import ctypes


def f(msg: list) -> int:
    return ctypes.c_int.from_address(msg[0]).value
