# @compiles: hatch
# CWE-121: Python has no stack arrays; memset at an arbitrary address can reach the stack.
import ctypes


def f(addr: int, n: int):
    ctypes.memset(addr, 0x41, n)
