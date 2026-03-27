
from rich import box
from rich.align import Align
from rich.console import Console
from rich.panel import Panel
from rich.text import Text


console = Console()


def render_run_blocked_panel() -> Panel:
    """
    Renderiza un panel informativo cuando no hay escenario cargado.
    """
    content = Text()
    content.append("No Active Scenario Loaded\n", style="bold white")
    content.append(
        "Attack execution cannot start without an operational scenario.\n\n",
        style="dim",
    )
    content.append("Required action\n", style="bold yellow")
    content.append('care db load --scenario "<scenario_name>"\n\n', style="bold cyan")
    content.append(
        "Load a scenario first and retry the operation.",
        style="yellow",
    )

    return Panel(
        Align.left(content),
        title="CARE / RUN BLOCKED",
        border_style="red",
        box=box.ROUNDED,
        padding=(1, 2),
    )


def main() -> None:
    """
    Punto de entrada de la vista.
    """
    console.print(render_run_blocked_panel())
