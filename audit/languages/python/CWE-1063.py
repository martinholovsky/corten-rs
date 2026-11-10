# @compiles
# CWE-1063: module-level code creates an instance when the module is imported.
class Store:
    def __init__(self):
        self.items = {}


INSTANCE = Store()
