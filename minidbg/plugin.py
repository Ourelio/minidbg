from __future__ import annotations

import argparse
import importlib
import importlib.util
import pkgutil
import sys
from pathlib import Path

from .context import Context


class PluginError(Exception):
    pass


class Plugin:
    """Subclasses with a `name` in minidbg/plugins/ or a --plugin-dir folder become commands."""

    name: str = ""
    aliases: tuple[str, ...] = ()
    help: str = ""

    @classmethod
    def add_arguments(cls, parser: argparse.ArgumentParser) -> None:
        pass

    def __init__(self, ctx: Context, args: argparse.Namespace):
        self.ctx = ctx
        self.dump = ctx.dump
        self.args = args

    def print(self, text: str = "") -> None:
        self.ctx.print(text)

    def run(self) -> None:
        raise NotImplementedError


def _plugins_in(module) -> list[type[Plugin]]:
    return [obj for obj in vars(module).values()
            if isinstance(obj, type) and issubclass(obj, Plugin) and obj.name
            and obj.__module__ == module.__name__]


def load_plugins(extra_dirs: list[str] = ()) -> dict[str, type[Plugin]]:
    from . import plugins as builtin

    modules = [importlib.import_module(f"{builtin.__name__}.{info.name}")
               for info in pkgutil.iter_modules(builtin.__path__)]
    for directory in extra_dirs:
        folder = Path(directory).expanduser()
        if not folder.is_dir():
            raise PluginError(f"plugin folder '{directory}' does not exist")
        for path in sorted(folder.glob("*.py")):
            module_name = f"minidbg_user_plugins.{path.stem}"
            spec = importlib.util.spec_from_file_location(module_name, path)
            module = importlib.util.module_from_spec(spec)
            sys.modules[module_name] = module
            try:
                spec.loader.exec_module(module)
            except Exception as exc:
                raise PluginError(f"couldn't load plugin file {path}: {exc}") from exc
            modules.append(module)

    found: dict[str, type[Plugin]] = {}
    taken: dict[str, str] = {}
    for module in modules:
        for cls in _plugins_in(module):
            for name in (cls.name, *cls.aliases):
                if name in taken:
                    raise PluginError(f"plugin name '{name}' is used by both {taken[name]} and {cls.__module__}")
                taken[name] = cls.__module__
            found[cls.name] = cls
    return found
