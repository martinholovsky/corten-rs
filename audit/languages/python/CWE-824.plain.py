# @rejected: invalid syntax. Did you mean 'not'?
# CWE-824: Python has no uninitialised declaration; a name is bound by assignment, and the C spelling does not parse.

def f():
    int x
    return x
