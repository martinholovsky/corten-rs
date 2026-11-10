# @compiles
# CWE-580: __copy__ builds a new object instead of calling super, so a subclass's copy has the wrong type.
class Account:
    def __init__(self, owner=0):
        self.owner = owner

    def __copy__(self):
        return Account(self.owner)


class Savings(Account):
    pass
