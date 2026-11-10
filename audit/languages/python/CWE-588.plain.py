# @rejected: invalid syntax
# CWE-588: Python has no reinterpreting cast; the C spelling does not parse.

def f(p):
    return (char *) p
