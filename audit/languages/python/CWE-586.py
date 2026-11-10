# @compiles
# CWE-586: __del__ is called explicitly, then again by the interpreter.
class Conn:
    def __del__(self):
        self.close()

    def close(self):
        pass


def f():
    c = Conn()
    c.__del__()
