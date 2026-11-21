from __future__ import annotations

import builtins

from robinshood import cli


def test_no_command_prints_help_instead_of_launching_tui(capsys):
    assert cli.main([]) == 0

    output = capsys.readouterr()
    assert "usage: robinshood" in output.out
    assert output.err == ""


def test_tui_command_explains_how_to_install_optional_dependency(monkeypatch, capsys):
    real_import = builtins.__import__

    def import_without_textual(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "textual":
            raise ModuleNotFoundError("No module named 'textual'", name="textual")
        return real_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", import_without_textual)

    assert cli.main(["tui"]) == 2

    output = capsys.readouterr()
    assert output.out == ""
    assert "optional TUI is not installed" in output.err
    assert "robinshood[tui]" in output.err


def test_tui_command_does_not_hide_unrelated_import_errors(monkeypatch):
    real_import = builtins.__import__

    def broken_app_import(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "robinshood.tui.app":
            raise ModuleNotFoundError("No module named 'unexpected'", name="unexpected")
        return real_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", broken_app_import)

    try:
        cli.main(["tui"])
    except ModuleNotFoundError as exc:
        assert exc.name == "unexpected"
    else:
        raise AssertionError("an unrelated import error was incorrectly suppressed")
