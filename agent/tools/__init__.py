# tools/__init__.py
from . import basic, weather, graph, audit, history

_modules = [basic, weather, graph, audit, history]

TOOLS = [t for m in _modules for t in m.TOOLS]
FUNCS = {k: v for m in _modules for k, v in m.FUNCS.items()}