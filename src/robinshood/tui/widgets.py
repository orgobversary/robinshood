from __future__ import annotations

from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, Label


class ConfirmModal(ModalScreen[bool]):
    """Require explicit approval before running active modules."""

    DEFAULT_CSS = """
    ConfirmModal {
        align: center middle;
    }
    #dialog {
        width: 60;
        height: auto;
        border: solid $border;
        background: $surface;
        padding: 1 2;
    }
    #buttons {
        height: auto;
        align: right middle;
        padding-top: 1;
    }
    #buttons Button {
        margin-left: 1;
    }
    """

    def __init__(self, message: str):
        super().__init__()
        self.message = message

    def compose(self) -> ComposeResult:
        with Vertical(id="dialog"):
            yield Label(self.message)
            with Horizontal(id="buttons"):
                yield Button("Cancel", id="confirm-no")
                yield Button("Run", id="confirm-yes")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss(event.button.id == "confirm-yes")
