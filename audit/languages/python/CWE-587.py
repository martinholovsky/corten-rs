# @compiles: hatch
# CWE-587: a hard-coded address is written.
import ctypes


def f():
    ctypes.c_int.from_address(0x1000).value = 1
