#footer 
from rich.console import Console
from rich.align import Align
from rich.text import Text

from theme_branding import VERSION, AUTHOR
from them_colors import MUTED

console = Console()


def show_footer():

    console.print()

    console.print(
        Align.center(
            Text(
                f"{VERSION} • Developed by {AUTHOR}",
                style=MUTED
            )
        )
    )

    console.print()
