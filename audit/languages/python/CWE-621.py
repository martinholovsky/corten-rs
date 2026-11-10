# @compiles
# CWE-621: request data is written into the module's globals.
def extract(params: dict):
    globals().update(params)
