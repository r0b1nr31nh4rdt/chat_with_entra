# tools/__init__.py
from . import basic, weather, graph, audit

_modules = [basic, weather, graph, audit]

TOOLS = [t for m in _modules for t in m.TOOLS]
FUNCS = {k: v for m in _modules for k, v in m.FUNCS.items()}