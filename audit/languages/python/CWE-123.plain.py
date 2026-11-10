# @rejected: cannot assign to expression here. Maybe you meant '==' instead of '='?
# CWE-123: Python has no pointer types; the C spelling of a fixed address does not parse.

def f():
    int *p = 0x1000
    return p
