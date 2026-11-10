# @rejected: invalid syntax
# CWE-843: Python has no reinterpreting cast; the C spelling does not parse.

def f(p):
    return (char *) p
