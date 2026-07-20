from pyfiglet import Figlet

from rich.console import Console
from rich.align import Align
from rich.text import Text
from theme_layout import SECTION_SPACING
from theme_branding import *
from them_colors import *
from theme_fonts import LOGO_FONT

console = Console()

def show_banner():
    fig = Figlet(font=LOGO_FONT)

    fig = Figlet(font=FONT)

    logo = fig.renderText(APP_NAME)

    console.print(
        Align.center(
            Text(
                logo,
                style=f"bold {PRIMARY}"
            )
        )
    )

    console.print()

    console.print(
        Align.center(
            Text(
                APP_SUBTITLE,
                style=SUBTITLE_COLOR
            )
        )
    )


    for _ in range(SECTION_SPACING):
        console.print()

    console.print()
