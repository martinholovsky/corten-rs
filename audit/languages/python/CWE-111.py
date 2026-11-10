# @compiles: hatch
# CWE-111: ctypes calls C code with none of Python's checks.
import ctypes


def f(s: bytes) -> int:
    return ctypes.CDLL(None).strlen(s)
