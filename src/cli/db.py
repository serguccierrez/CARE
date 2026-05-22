"""
Database CLI de CARE: Gestión de escenarios, activos y operaciones de base de datos.
Interfaz para cargar, inspeccionar y eliminar escenarios de análisis de ciberseguridad.
"""

#==============================================[IMPORTS]==============================================#
from rich.console import Console
from rich.text import Text
from rich.panel import Panel
from rich.table import Table
from rich.align import Align
from rich.layout import Layout
from rich import box

import src.graph.grafo as grafo
from pathlib import Path



DB_PATH = Path(__file__).parent.parent / "database" / "tfg_catalog.db"



#==============================================[CONSOLE Y RENDERIZADO]==============================================#

console = Console()


def content_panel_height(rows: list) -> int:
    """
    Calcula la altura del panel principal en funcion del numero de elementos mostrados.
    """
    visible_rows = len(rows) if rows else 1
    return 7 + visible_rows


def render_db_header() -> Panel:
    """
    Renderiza el encabezado del módulo de base de datos.
    
    Returns:
        Panel: Componente gráfico con título y subtítulo centrado.
    """
    header_text = Text(justify="center")
    header_text.append("CARE / DATABASE\n", style="bold cyan")
    header_text.append("Scenario Management and Data Operations", style="dim")

    header = Panel(
        Align.center(header_text, vertical="middle"),
        border_style="cyan",
        box=box.ROUNDED
    )

    return header


def render_scenarios_table(scenarios: list, selected_scenario: str) -> Panel:
    """
    Renderiza tabla de escenarios almacenados en la base de datos.
    
    Args:
        scenarios (list): Lista de tuplas con estructura:
                         [(scenario_pk, scenario_name, description, source_file, created_at), ...]
    
    Returns:
        Panel: Tabla formateada con escenarios.
    """
    table = Table(show_header=True, header_style="bold cyan", expand=True, box=box.SIMPLE)
    table.add_column("ID", style="bright_white", width=5, justify="center", no_wrap=True)
    table.add_column("Scenario Name", style="green", min_width=20, justify="center", overflow="fold")
    table.add_column("Source File", style="yellow", min_width=28, justify="center", overflow="fold")
    table.add_column("Created At", style="blue", min_width=20, justify="center", no_wrap=True)

    for scenario in scenarios:
        scenario_pk, scenario_name, description, source_file, created_at = scenario
        source_name = Path(source_file).name if source_file else "N/A"
        
        if scenario_name == selected_scenario:
            scenario_name = f" * {scenario_name} "

        table.add_row(
            str(scenario_pk),
            scenario_name or "Unknown",
            source_name,
            created_at or "N/A"
        )

    panel = Panel(
        table,
        title="Stored Scenarios",
        border_style="yellow",
        padding=(0, 1),
    )

    return panel


def render_assets_table(assets: list, selected_scenario: str) -> Panel:
    """
    Renderiza tabla de activos asociados a un escenario concreto.

    Args:
        assets (list): Lista de tuplas con estructura:
                      [(asset_pk, scenario_fk, asset_id, name, asset_type, domain,
                        criticality, cia_c, cia_i, cia_a, operational_state), ...]
        selected_scenario (str): Nombre del escenario cuyos activos se muestran.

    Returns:
        Panel: Tabla formateada con los activos del escenario.
    """
    table = Table(show_header=True, header_style="bold cyan", expand=True, box=box.SIMPLE)
    table.add_column("Asset ID", style="bright_white", min_width=12, justify="center", no_wrap=True)
    table.add_column("Name", style="green", min_width=22, justify="center", overflow="fold")
    table.add_column("Type", style="yellow", min_width=14, justify="center", overflow="fold")
    table.add_column("Domain", style="blue", min_width=12, justify="center", no_wrap=True)
    table.add_column("Criticality", style="magenta", min_width=11, justify="center", no_wrap=True)

    for asset in assets:
        _, _, asset_id, name, asset_type, domain, criticality, _, _, _, _ = asset
        table.add_row(
            asset_id,
            name or "Unknown",
            asset_type or "N/A",
            domain or "N/A",
            f"{float(criticality):.1f}",
        )

    panel = Panel(
        table,
        title=f"Assets From Scenario: {selected_scenario}",
        border_style="yellow",
        padding=(0, 1),
    )

    return panel


def render_operations_menu() -> Panel:
    """
    Renderiza el menú de operaciones disponibles con formato profesional.
    
    Returns:
        Panel: Panel con opciones de operaciones.
    """
    operations_text = Text()
    
    # Operación 1
    operations_text.append("  [1] python -m src.cli.care db create --scenario <scenario_name> --description <description> --source <source_file>\n", style="cyan")
    operations_text.append("      Create a new scenario from an Excel asset/dependency catalog\n\n", style="dim")
    
    # Operación 2
    operations_text.append("  [2] python -m src.cli.care db load --scenario <scenario_name>\n", style="cyan")
    operations_text.append("      Import a new scenario from the DB catalog\n\n", style="dim")
    
    # Operación 3
    operations_text.append("  [3] python -m src.cli.care db delete --scenario <scenario_name>\n", style="cyan")
    operations_text.append("      Remove a stored scenario and all associated assets and dependencies\n\n", style="dim")
    
    # Operación 4
    operations_text.append("  [4] python -m src.cli.care db asset-list --scenario <scenario_name>\n", style="cyan")
    operations_text.append("      Display all registered assets for a selected scenario\n\n", style="dim")

    
    panel = Panel(
        operations_text,
        title="Available Operations",
        border_style="green",
        padding=(1, 2),
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
    status_text.append("Select database operation: ", style="bold green")
    
    return status_text


def build_db_interface(scenarios: list, selected_scenario: str, show_assets: bool = False) -> None:
    """
    Ensambla y renderiza la interfaz completa de base de datos usando Layout.
    
    Organiza componentes en un layout jerárquico: encabezado, tabla de escenarios,
    menú de operaciones y prompt del sistema.
    
    Args:
        scenarios (list): Lista de tuplas con datos de escenarios almacenados.
        selected_scenario (str, optional): Nombre del escenario seleccionado.
        show_assets (bool, optional): Si es True, muestra los activos del escenario
        seleccionado en lugar de la tabla de escenarios.
    """
    console.clear()

    if show_assets and selected_scenario:
        rows = grafo.list_assets_by_scenario(str(DB_PATH), selected_scenario)
        main_panel = render_assets_table(rows, selected_scenario)
    else:
        rows = scenarios
        main_panel = render_scenarios_table(scenarios, selected_scenario)

    main_panel_height = content_panel_height(rows)
    
    # Crear layout principal dividido en 4 secciones verticales
    layout = Layout()
    layout.split_column(
        Layout(name="header", size=5),
        Layout(name="content", size=main_panel_height),
        Layout(name="operations", size=18),
        Layout(name="prompt", size=3),
    )
    
    # Renderizar y asignar componentes a cada sección
    layout["header"].update(render_db_header())
    
    operations_panel = render_operations_menu()

    layout["content"].update(main_panel)
    layout["operations"].update(operations_panel)

    layout["prompt"].update(Align.left(render_system_ready()))
    
    # Imprimir el layout completo
    console.print(layout)


def main(selected_scenario: str = None, show_assets: bool = False) -> None:
    """
    Función principal de demostración de la interfaz de base de datos.
    
    Renderiza la interfaz con datos de ejemplo para visualización.
    """
    sample_scenarios = grafo.list_scenarios(str(DB_PATH))

    
    build_db_interface(sample_scenarios, selected_scenario, show_assets)


if __name__ == "__main__":
    main()
