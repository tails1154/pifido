"""Piannaple screen-module loader.

Each module is an ordinary Python file in this directory with a
``register(manager)`` function. A broken optional module is skipped so it
cannot take down the home screen.
"""

from importlib import import_module
from pathlib import Path


def discover(manager):
    package_dir = Path(__file__).parent
    for path in sorted(package_dir.glob("*.py")):
        if path.name.startswith("_"):
            continue
        module_name = f"{__name__}.{path.stem}"
        try:
            module = import_module(module_name)
            register = getattr(module, "register", None)
            if register is not None:
                register(manager)
        except Exception as exc:  # optional modules must be non-fatal
            print(f"Piannaple module {module_name} skipped: {exc}")
