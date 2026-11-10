# @compiles
# CWE-470: input names the class that is instantiated.
import importlib


def make(module: str, cls: str):
    return getattr(importlib.import_module(module), cls)()
