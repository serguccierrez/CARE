
from rich import box
from rich.align import Align
from rich.console import Console
from rich.panel import Panel
from rich.text import Text


console = Console()


def render_message_panel(
    title: str,
    header: str,
    description: str,
    action_title: str | None = None,
    action_text: str | None = None,
    footer: str | None = None,
    border_style: str = "red",
) -> Panel:
    """
    Renderiza un panel simple y reutilizable para mensajes de error o bloqueo.
    """
    content = Text()
    content.append(f"{header}\n", style="bold white")
    content.append(f"{description}\n\n", style="dim")

    if action_title:
        content.append(f"{action_title}\n", style="bold yellow")

    if action_text:
        content.append(f"{action_text}\n\n", style="bold cyan")

    if footer:
        content.append(footer, style="yellow")

    return Panel(
        Align.left(content),
        title=title,
        border_style=border_style,
        box=box.ROUNDED,
        padding=(1, 2),
    )


def render_run_blocked_panel() -> Panel:
    """
    Renderiza un panel informativo cuando no hay escenario cargado.
    """
    return render_message_panel(
        title="CARE / RUN BLOCKED",
        header="No Active Scenario Loaded",
        description="Attack execution cannot start without an operational scenario.",
        action_title="Required action",
        action_text='python -m src.cli.care db load --scenario "<scenario_name>"',
        footer="Load a scenario first and retry the operation.",
    )


def main(
    title: str = "CARE / RUN BLOCKED",
    header: str = "No Active Scenario Loaded",
    description: str = "Attack execution cannot start without an operational scenario.",
    action_title: str | None = "Required action",
    action_text: str | None = 'python -m src.cli.care db load --scenario "<scenario_name>"',
    footer: str | None = "Load a scenario first and retry the operation.",
    border_style: str = "red",
) -> None:
    """
    Punto de entrada de la vista.
    """
    console.print(
        render_message_panel(
            title=title,
            header=header,
            description=description,
            action_title=action_title,
            action_text=action_text,
            footer=footer,
            border_style=border_style,
        )
    )
