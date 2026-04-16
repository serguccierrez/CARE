"""
Report CLI de CARE: Gestio
n de runs y reportes persistidos.
Interfaz para guardar, listar e inspeccionar ejecuciones de anÃ¡lisis almacenadas.
"""

#==============================================[IMPORTS]==============================================#
from rich.console import Console
from rich.text import Text
from rich.panel import Panel
from rich.table import Table
from rich.align import Align
from rich.layout import Layout
from rich import box


#==============================================[CONSOLE Y RENDERIZADO]==============================================#

console = Console()


def content_panel_height(rows: list) -> int:
    """
    Calcula la altura del panel principal en funcion del numero de elementos mostrados.
    """
    visible_rows = len(rows) if rows else 1
    return 5 + visible_rows


def render_report_header(scenario_name: str = None) -> Panel:
    """
    Renderiza el encabezado del mÃ³dulo de reportes.
    
    Returns:
        Panel: Componente grÃ¡fico con tÃ­tulo y subtÃ­tulo centrado.
    """
    header_text = Text(justify="center")
    header_text.append("CARE / REPORTS\n", style="bold cyan")
    if scenario_name:
        header_text.append(f"Stored Analysis Runs and Narrative Reports | Scenario: {scenario_name}", style="dim")
    else:
        header_text.append("Stored Analysis Runs and Narrative Reports", style="dim")

    header = Panel(
        Align.center(header_text, vertical="middle"),
        border_style="cyan",
        box=box.ROUNDED
    )

    return header


def render_runs_table(runs: list, selected_run: str = None, scenario_name: str = None) -> Panel:
    """
    Renderiza tabla de runs almacenados en la base de datos.
    
    Args:
        runs (list): Lista de tuplas con estructura:
                    [(run_pk, run_name, description, created_at), ...]
        selected_run (str, optional): Identificador del run seleccionado.
    
    Returns:
        Panel: Tabla formateada con runs persistidos.
    """
    table = Table(show_header=True, header_style="bold cyan", expand=True, box=box.SIMPLE)
    table.add_column("Run ID", style="bright_white", width=8, justify="center", no_wrap=True)
    table.add_column("Run Name", style="green", min_width=24, justify="center", overflow="fold")
    table.add_column("Description", style="yellow", min_width=26, justify="center", overflow="fold")
    table.add_column("Created At", style="blue", min_width=20, justify="center", no_wrap=True)

    for run in runs:
        run_pk, run_name, description, created_at = run[:4]

        visible_name = run_name or "Unknown"
        if selected_run is not None and str(run_pk) == str(selected_run):
            visible_name = f" * {visible_name} "

        table.add_row(
            str(run_pk),
            visible_name,
            description or "N/A",
            created_at or "N/A"
        )

    panel = Panel(
        table,
        title=f"Stored Runs for Scenario: {scenario_name}" if scenario_name else "Stored Runs",
        border_style="yellow",
        padding=(0, 1),
    )

    return panel


def render_saved_run_summary(saved_run: dict) -> Panel:
    """
    Renderiza un resumen del run que acaba de guardarse.
    
    Args:
        saved_run (dict): Diccionario resumen del guardado realizado.
    
    Returns:
        Panel: Panel con el resumen del nuevo run almacenado.
    """
    summary_text = Text()
    summary_text.append("Run stored successfully\n\n", style="bold green")
    summary_text.append("Run ID: ", style="bold white")
    summary_text.append(f"{saved_run.get('run_pk', 'N/A')}\n", style="cyan")
    summary_text.append("Scenario: ", style="bold white")
    summary_text.append(f"{saved_run.get('scenario_name', 'N/A')}\n", style="cyan")
    summary_text.append("Run Name: ", style="bold white")
    summary_text.append(f"{saved_run.get('run_name', 'N/A')}\n", style="cyan")
    summary_text.append("Created At: ", style="bold white")
    summary_text.append(f"{saved_run.get('created_at', 'N/A')}\n", style="cyan")

    panel = Panel(
        summary_text,
        title="Saved Run Summary",
        border_style="green",
        padding=(1, 2),
    )

    return panel


def render_operations_menu() -> Panel:
    """
    Renderiza el menÃº de operaciones disponibles con formato profesional.
    
    Returns:
        Panel: Panel con opciones de operaciones.
    """
    operations_text = Text()

    operations_text.append("  [1] python -m src.cli.care reports", style="cyan")
    operations_text.append(" - list active scenario runs\n", style="dim")
    operations_text.append("  [2] python -m src.cli.care reports --scenario <scenario_name>", style="cyan")
    operations_text.append(" - list a specific scenario\n", style="dim")
    operations_text.append("  [3] python -m src.cli.care reports save --filename <report_name.md> [--description \"<text>\"]", style="cyan")
    operations_text.append(" - save current run\n", style="dim")
    operations_text.append("  [4] python -m src.cli.care reports load --run_name <run_name>", style="cyan")
    operations_text.append(" - restore run and open dashboard\n", style="dim")
    operations_text.append("  [5] python -m src.cli.care dashboard", style="cyan")
    operations_text.append(" - visualize current dashboard", style="dim")

    panel = Panel(
        operations_text,
        title="Available Operations",
        border_style="green",
        padding=(0, 1),
    )

    return panel


def render_system_ready() -> Text:
    """
    Renderiza mensaje de sistema listo para recibir comandos.
    
    Returns:
        Text: Texto formateado con estado del sistema.
    """
    status_text = Text()
    status_text.append("System ready. ", style="white")
    status_text.append("Select report operation: ", style="bold green")

    return status_text


def build_report_interface(
    runs: list = None,
    selected_run: str = None,
    saved_run: dict = None,
    show_saved_summary: bool = True,
    scenario_name: str = None,
) -> None:
    """
    Ensambla y renderiza la interfaz completa de reportes usando Layout.
    
    Args:
        runs (list, optional): Lista de runs persistidos.
        selected_run (str, optional): Identificador del run seleccionado.
        saved_run (dict, optional): Resumen del run recientemente guardado.
        show_saved_summary (bool, optional): Si es True, muestra el resumen del run guardado.
    """
    console.clear()

    rows = runs or []

    if show_saved_summary and saved_run:
        main_panel = render_saved_run_summary(saved_run)
        main_panel_height = 12
    else:
        main_panel = render_runs_table(rows, selected_run, scenario_name)
        main_panel_height = content_panel_height(rows)

    # Crear layout principal dividido en 4 secciones verticales
    layout = Layout()
    layout.split_column(
        Layout(name="header", size=5),
        Layout(name="content", size=main_panel_height),
        Layout(name="operations", size=10),
        Layout(name="prompt", size=2),
    )

    # Renderizar y asignar componentes a cada secciÃ³n
    layout["header"].update(render_report_header(scenario_name))
    layout["content"].update(main_panel)
    layout["operations"].update(render_operations_menu())
    layout["prompt"].update(Align.left(render_system_ready()))

    # Imprimir el layout completo
    console.print(layout)


def main(
    runs: list = None,
    selected_run: str = None,
    saved_run: dict = None,
    show_saved_summary: bool = False,
    scenario_name: str = None,
) -> None:
    """
    Funcin principal de demostracion de la interfaz de reportes.
    
    Renderiza la interfaz de listado de runs o el resumen de guardado.
    """
    build_report_interface(runs, selected_run, saved_run, show_saved_summary, scenario_name)


if __name__ == "__main__":
    main()
