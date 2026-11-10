# @compiles
# CWE-1097: __eq__ is not defined, so stored records compare by identity.
class Rec:
    def __init__(self, rid: int):
        self.rid = rid


def same(a: Rec, b: Rec) -> bool:
    return a == b
