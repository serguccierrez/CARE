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


def render_scenarios_table(scenarios: list) -> Panel:
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


def render_operations_menu() -> Panel:
    """
    Renderiza el menú de operaciones disponibles con formato profesional.
    
    Returns:
        Panel: Panel con opciones de operaciones.
    """
    operations_text = Text()
    
    # Operación 1
    operations_text.append("  [1] python care.py create-scenario\n", style="cyan")
    operations_text.append("      Create a new scenario from an Excel asset/dependency catalog\n\n", style="dim")
    
    # Operación 2
    operations_text.append("  [2] python care.py load-scenario\n", style="cyan")
    operations_text.append("      Import a new scenario from an Excel asset/dependency catalog\n\n", style="dim")
    
    # Operación 3
    operations_text.append("  [3] python care.py delete-scenario", style="cyan")
    operations_text.append(" --<scenario_name>\n", style="cyan")
    operations_text.append("      Remove a stored scenario and all associated assets and dependencies\n\n", style="dim")
    
    # Operación 4
    operations_text.append("  [4] python care.py inspect-scenario\n", style="cyan")
    operations_text.append("      Display all registered assets for a selected scenario\n\n", style="dim")
    
    # Operación 5
    operations_text.append("  [5] python care.py return-to-main\n", style="cyan")
    operations_text.append("      Exit database operations and return to CARE main interface\n", style="dim")
    
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


def build_db_interface(scenarios: list) -> None:
    """
    Ensambla y renderiza la interfaz completa de base de datos usando Layout.
    
    Organiza componentes en un layout jerárquico: encabezado, tabla de escenarios,
    menú de operaciones y prompt del sistema.
    
    Args:
        scenarios (list): Lista de tuplas con datos de escenarios almacenados.
    """
    console.clear()
    
    # Crear layout principal dividido en 4 secciones verticales
    layout = Layout()
    layout.split_column(
        Layout(name="header", size=5),
        Layout(name="scenarios", size=10),
        Layout(name="operations", size=18),
        Layout(name="prompt", size=3),
    )
    
    # Renderizar y asignar componentes a cada sección
    layout["header"].update(render_db_header())
    layout["scenarios"].update(render_scenarios_table(scenarios))
    layout["operations"].update(render_operations_menu())
    layout["prompt"].update(Align.left(render_system_ready()))
    
    # Imprimir el layout completo
    console.print(layout)


def main():
    """
    Función principal de demostración de la interfaz de base de datos.
    
    Renderiza la interfaz con datos de ejemplo para visualización.
    """
    sample_scenarios = grafo.list_scenarios(str(DB_PATH))

    
    build_db_interface(sample_scenarios)


if __name__ == "__main__":
    main()
