# @compiles
# CWE-582: a module-level list is writable by any importer.
ADMIN_IDS = [1, 2, 3]


def tamper():
    ADMIN_IDS[0] = 999
