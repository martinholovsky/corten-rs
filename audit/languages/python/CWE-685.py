# @compiles
# CWE-685: % formatting is given fewer values than the format consumes.
def f(x: int) -> str:
    return "%d %d" % (x,)
