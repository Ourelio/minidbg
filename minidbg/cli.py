from __future__ import annotations

import argparse
import os
import sys

from .context import CommandError, Context
from .minidump import MiniDump, MiniDumpError
from .plugin import Plugin, PluginError, load_plugins


def _hex(text: str) -> int:
    return int(text.replace("`", ""), 16)


def build_parser(plugins: dict[str, type[Plugin]]) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="minidbg",
        description="WinDbg-style analysis of Windows user-mode minidumps (.dmp), one plugin per run.",
        epilog="examples:\n  minidbg stealer.DMP lm\n  minidbg stealer.DMP address -f PAGE_READWRITE,MEM_PRIVATE,Unknown\n"
               "  minidbg stealer.DMP s -a 'flag{'\n\nplugin options: minidbg <dump> <plugin> -h",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("-p", "--plugin-dir", action="append", default=[], metavar="DIR",
                        help="also load plugins from the .py files in DIR (repeatable)")
    parser.add_argument("--force", action="store_true", help="keep going even if the MDMP signature is wrong")
    parser.add_argument("dump", help="path to the .dmp file")

    common = argparse.ArgumentParser(add_help=False)
    selection = common.add_argument_group("thread selection (for registers and @reg in addresses)")
    selection.add_argument("-t", "--thread", type=int, metavar="N",
                           help="use thread N from the 'threads' list (default: the crashing thread, else 0)")
    selection.add_argument("--tid", type=_hex, metavar="TID", help="use the thread with this id (hex)")
    selection.add_argument("--ecxr", action="store_true",
                           help="use the registers saved with the exception (crash dumps)")

    sub = parser.add_subparsers(dest="plugin", metavar="plugin", title="plugins", required=True)
    for name in sorted(plugins):
        cls = plugins[name]
        plugin_parser = sub.add_parser(name, aliases=list(cls.aliases), help=cls.help, description=cls.help,
                                       parents=[common])
        cls.add_arguments(plugin_parser)
        plugin_parser.set_defaults(plugin_class=cls)
    return parser


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    early = argparse.ArgumentParser(add_help=False)
    early.add_argument("-p", "--plugin-dir", action="append", default=[])
    plugin_dirs = early.parse_known_args(argv)[0].plugin_dir
    try:
        plugins = load_plugins(plugin_dirs)
    except PluginError as exc:
        print(f"minidbg: {exc}", file=sys.stderr)
        return 2

    args = build_parser(plugins).parse_args(argv)
    try:
        dump = MiniDump(args.dump, force=args.force)
    except (OSError, MiniDumpError) as exc:
        print(f"minidbg: {exc}", file=sys.stderr)
        return 1

    with dump:
        for warning in dump.warnings:
            print(f"minidbg: warning: {warning}", file=sys.stderr)
        try:
            ctx = Context(dump, sys.stdout, thread_index=args.thread, thread_id=args.tid,
                          exception_context=args.ecxr)
            args.plugin_class(ctx, args).run()
            sys.stdout.flush()
        except (CommandError, MiniDumpError) as exc:
            print(f"minidbg: error: {exc}", file=sys.stderr)
            return 1
        except BrokenPipeError:
            # output was piped into something like `head` that stopped reading
            os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
            return 0
    return 0
