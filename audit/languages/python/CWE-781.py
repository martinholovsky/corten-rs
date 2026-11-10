# @compiles: hatch
# CWE-781: an IOCTL-style handler reads through a raw user address.
import ctypes


def handle(user_buffer: int, length: int) -> int:
    return ctypes.c_ubyte.from_address(user_buffer + length - 1).value
