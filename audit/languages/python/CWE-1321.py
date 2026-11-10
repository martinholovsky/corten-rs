# @compiles
# CWE-1321: input names a class attribute that setattr overwrites for every instance.
class Config:
    debug = False


def update(obj, key: str, value):
    setattr(type(obj), key, value)
