# @compiles
# CWE-1098: copy.copy shares the list between both objects.
import copy


class Buf:
    def __init__(self):
        self.data = [0] * 8


def f():
    a = Buf()
    b = copy.copy(a)
    b.data[0] = 1
