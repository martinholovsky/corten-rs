# @compiles
# CWE-568: __del__ in a subclass does not call the base class's __del__.
class Base:
    def __del__(self):
        self.release()

    def release(self):
        pass


class Conn(Base):
    def __del__(self):
        pass
