#startup 
from ui.components.banner import show_banner
from ui.components.divider import draw_divider
from ui.components.footer import show_footer
from ui.components.loading import show_loading

def show_startup():
    show_banner()

    draw_divider()

    show_loading()

    show_footer()
