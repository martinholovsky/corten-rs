# @compiles
# CWE-1055: a class inherits from two concrete classes.
class Logger:
    level = 0


class Store:
    size = 0


class Service(Logger, Store):
    pass
