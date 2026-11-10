# @compiles
# CWE-98: input names the module that is imported and run.
import importlib


def load(name: str):
    return importlib.import_module(name)
