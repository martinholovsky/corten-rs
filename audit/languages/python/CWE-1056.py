# @compiles
# CWE-1056: a function takes any number of positional arguments.
def total(*xs):
    return sum(xs)
