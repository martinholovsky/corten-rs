# @rejected: invalid syntax. Did you mean 'del'?
# CWE-763: Python has no explicit free; the C++ spelling does not parse (del only unbinds a name).

def f(p):
    delete p
