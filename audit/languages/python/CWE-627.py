# @compiles
# CWE-627: input names the variable that is read.
def lookup(name: str):
    return globals()[name]
