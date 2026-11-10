# @rejected: can't use starred expression here
# CWE-119: Python has no pointer dereference; the C spelling does not parse.

def f(a, i):
    return *(a + i)
