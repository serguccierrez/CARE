"""
Attack CLI de CARE: Configuracion operativa de ataques simulados y controlados.
Interfaz para seleccionar activo inicial, TTPs y modo de ejecucion del analisis.
"""

#==============================================[IMPORTS]==============================================#
from pathlib import Path
import random

from rich import box
from rich.align import Align
from rich.console import Console
from rich.layout import Layout
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

import src.cyberrecom.mitre as mitre
import src.graph.grafo as grafo


#==============================================[CONSTANTES]==============================================#
DB_PATH = Path(__file__).parent.parent / "database" / "tfg_catalog.db"
MAX_ASSETS_DISPLAY = 6
MAX_TTPS_DISPLAY = 8


#==============================================[CONSOLE Y RENDERIZADO]==============================================#
console = Console()
ATTACK_WIDE_LAYOUT_BREAKPOINT = 150


def confidence_color(value) -> str:
    """
    Devuelve el color semaforico usado para representar el nivel de confianza.
    """
    if 0.0 <= value < 0.5:
        return "green"
    if 0.5 <= value < 0.6:
        return "yellow"
    if 0.6 <= value <= 0.8:
        return "orange3"
    if 0.8 < value <= 1.0:
        return "red"
    return "white"


def render_attack_header() -> Panel:
    """
    Renderiza el encabezado del modulo de ejecucion de ataques.
    """
    header_text = Text(justify="center")
    header_text.append("CARE / ATTACK OPERATIONS\n", style="bold cyan")
    header_text.append("Threat Injection and Countermeasure Analysis Console", style="dim")

    return Panel(
        Align.center(header_text, vertical="middle"),
        border_style="cyan",
        box=box.ROUNDED,
    )


def render_context_panel(
    scenario_name: str,
    total_assets: int,
    total_ttps: int,
    panel_height: int | None = None,
) -> Panel:
    """
    Renderiza el contexto operativo actual del escenario activo.
    """
    context = Text()
    context.append("Active Scenario: ", style="bold white")
    context.append(f"{scenario_name}\n", style="bold green")
    context.append("Registered Assets: ", style="bold white")
    context.append(f"{total_assets}\n", style="cyan")
    context.append("Available MITRE TTPs: ", style="bold white")
    context.append(f"{total_ttps}\n", style="cyan")
    context.append("Displayed Samples: ", style="bold white")
    context.append("Random asset subset and random TTP subset\n", style="yellow")
    context.append("Execution Scope: ", style="bold white")
    context.append("Initial asset selection and threat vector injection", style="yellow")

    return Panel(
        Align.left(context),
        title="Current Operational Context",
        border_style="yellow",
        padding=(1, 2),
        height=panel_height,
    )


def render_assets_table(assets: list, scenario_name: str, panel_height: int | None = None) -> Panel:
    """
    Renderiza una tabla con los activos del escenario activo.
    """
    table = Table(show_header=True, header_style="bold cyan", expand=True, box=box.SIMPLE)
    table.add_column("Asset ID", style="bright_white", min_width=12, justify="center", no_wrap=True)
    table.add_column("Name", style="green", min_width=20, justify="left", overflow="fold")
    table.add_column("Domain", style="blue", min_width=10, justify="center", no_wrap=True)
    table.add_column("Criticality", style="magenta", min_width=13, justify="center", no_wrap=True)

    if not assets:
        table.add_row("-", "No assets available", "-", "-", "-")
    else:
        sample_size = min(MAX_ASSETS_DISPLAY, len(assets))
        sampled_assets = random.sample(assets, sample_size)

        for asset in sampled_assets:
            _, _, asset_id, name, _, domain, criticality, _, _, _, _ = asset
            table.add_row(
                asset_id,
                name,
                domain,
                f"{float(criticality):.1f}",
            )

    return Panel(
        table,
        title="Random Initial Asset Candidates",
        subtitle=f"View full asset inventory: python -m src.cli.care db asset-list --scenario \"{scenario_name}\"",
        border_style="blue",
        padding=(0, 1),
        height=panel_height,
    )


def render_ttps_table(ttps: list, panel_height: int | None = None) -> Panel:
    """
    Renderiza una tabla resumida con TTPs disponibles para inyeccion.
    """
    table = Table(show_header=True, header_style="bold cyan", expand=True, box=box.SIMPLE)
    table.add_column("TTP ID", style="bright_white", min_width=10, justify="center", no_wrap=True)
    table.add_column("Technique Name", style="green", min_width=28, justify="left", overflow="fold")

    if not ttps:
        table.add_row("-", "No TTPs available")
    else:
        sample_size = min(MAX_TTPS_DISPLAY, len(ttps))
        sampled_ttps = random.sample(ttps, sample_size)

        for ttp_id, ttp_name in sampled_ttps:
            table.add_row(ttp_id, ttp_name)

    return Panel(
        table,
        title="Random Threat Technique Sample",
        subtitle="Use attack select to inject a known MITRE TTP into the active scenario",
        border_style="red",
        padding=(0, 1),
        height=panel_height,
    )


def analysis_panel_height(assets: list, ttps: list) -> int:
    """
    Calcula una altura comun para los paneles de assets y TTPs
    a partir del mayor numero de filas mostradas.
    """
    visible_assets = min(len(assets), MAX_ASSETS_DISPLAY) if assets else 1
    visible_ttps = min(len(ttps), MAX_TTPS_DISPLAY) if ttps else 1
    max_rows = max(visible_assets, visible_ttps, 1)

    return 7 + max_rows


def render_execution_modes_panel() -> Panel:
    """
    Renderiza los modos de operacion disponibles para la ejecucion del ataque.
    """
    modes_text = Text()
    modes_text.append("  [1] Random Attack Simulation\n", style="cyan")
    modes_text.append("      Fully automatic run: random asset, random TTPs and random confidence values.\n", style="dim")
    modes_text.append("      python -m src.cli.care attack run --random\n\n", style="yellow")

    modes_text.append("  [2] Controlled Attack Injection\n", style="cyan")
    modes_text.append("      Choose asset, TTP and/or confidence before running the simulation.\n", style="dim")
    modes_text.append("      Any value left unset is filled randomly at runtime.\n", style="dim")
    modes_text.append("      python -m src.cli.care attack select --asset <asset_id> --ttp <Txxxx> --confidence <0.0-1.0>\n", style="yellow")
    modes_text.append("      python -m src.cli.care attack run\n", style="yellow")


    return Panel(
        modes_text,
        title="Execution Modes",
        border_style="green",
        padding=(1, 2),
    )


def render_selected_vectors_panel(context: dict, panel_height: int | None = None) -> Panel:
    """
    Renderiza los vectores de amenaza seleccionados en modo controlado.
    """
    selected_assets = context.get("selected_asset", []) if context else []
    selected_ttps = context.get("selected_ttps", []) if context else []
    selected_confidences = context.get("selected_confidences", []) if context else []
    mode = context.get("mode", "N/A") if context else "N/A"

    table = Table(show_header=True, header_style="bold cyan", expand=True, box=box.SIMPLE)
    table.add_column("Asset", style="bright_white", min_width=10, justify="center", no_wrap=True)
    table.add_column("TTP", style="green", min_width=9, justify="center", no_wrap=True)
    table.add_column("Conf.", style="yellow", min_width=7, justify="center", no_wrap=True)

    max_len = max(len(selected_assets), len(selected_ttps), len(selected_confidences), 0)

    if max_len == 0:
        table.add_row("-", "-", "-")
    else:
        for idx in range(max_len):
            asset = selected_assets[idx] if idx < len(selected_assets) else "-"
            ttp = selected_ttps[idx] if idx < len(selected_ttps) else "-"
            confidence = selected_confidences[idx] if idx < len(selected_confidences) else "-"

            if isinstance(confidence, (int, float)):
                confidence_value = f"{float(confidence):.2f}"
                confidence_render = Text(
                    confidence_value,
                    style=f"bold {confidence_color(float(confidence))}",
                )
            else:
                confidence_render = str(confidence)

            table.add_row(str(asset), str(ttp), confidence_render)

    return Panel(
        table,
        title=f"Selected Vectors [{mode}]",
        border_style="magenta",
        padding=(0, 1),
        height=panel_height,
    )


def render_system_ready() -> Text:
    """
    Renderiza el estado final del sistema listo para lanzar el analisis.
    """
    status = Text()
    status.append("System ready. ", style="white")
    status.append("Select attack configuration and execute operation.", style="bold green")
    return status


def build_attack_interface(scenario_name: str, assets: list, ttps: list, context: dict | None = None) -> None:
    """
    Ensambla la interfaz completa del modulo de ataque.
    """
    console.clear()
    console_width = console.size.width
    context_section_height = 11 if console_width >= ATTACK_WIDE_LAYOUT_BREAKPOINT else 18

    layout = Layout()
    layout.split_column(
        Layout(name="header", size=5),
        Layout(name="context", size=context_section_height),
        Layout(name="analysis", size=15),
        Layout(name="modes", size=13),
        Layout(name="prompt", size=3),
    )

    common_panel_height = analysis_panel_height(assets, ttps)

    top_panel_height = context_section_height if console_width >= ATTACK_WIDE_LAYOUT_BREAKPOINT else None
    context_panel = render_context_panel(scenario_name, len(assets), len(ttps), top_panel_height)
    selected_vectors_panel = render_selected_vectors_panel(context, top_panel_height)
    assets_panel = render_assets_table(assets, scenario_name, common_panel_height)
    ttps_panel = render_ttps_table(ttps, common_panel_height)

    if console_width >= ATTACK_WIDE_LAYOUT_BREAKPOINT:
        context_content = Table.grid(expand=True)
        context_content.add_column(ratio=3)
        context_content.add_column(ratio=2)
        context_content.add_row(
            context_panel,
            selected_vectors_panel,
        )

        analysis_content = Table.grid(expand=True)
        analysis_content.add_column(ratio=6)
        analysis_content.add_column(ratio=7)
        analysis_content.add_row(
            assets_panel,
            ttps_panel,
        )
    else:
        context_content = Table.grid(expand=True)
        context_content.add_column()
        context_content.add_row(context_panel)
        context_content.add_row(selected_vectors_panel)

        analysis_content = Table.grid(expand=True)
        analysis_content.add_column()
        analysis_content.add_row(assets_panel)
        analysis_content.add_row(ttps_panel)

    layout["header"].update(render_attack_header())
    layout["context"].update(context_content)
    layout["analysis"].update(analysis_content)
    layout["modes"].update(render_execution_modes_panel())
    layout["prompt"].update(Align.left(render_system_ready()))

    console.print(layout)


def resolve_active_scenario(context):
    """
    Resuelve el escenario operativo activo.
    Actualmente selecciona el ultimo escenario almacenado como contexto por defecto.
    """
    scenarios = grafo.list_scenarios(str(DB_PATH))
    if not scenarios:
        return None
    
    if context is None:
        return None
    scenario = context["active_scenario"]
    
    return scenario


def main(context = None):
    """
    Punto de entrada de demostracion para la pantalla de ataque.
    """
    active_scenario = resolve_active_scenario(context)

    if active_scenario is None:
        build_attack_interface("No active scenario", [], [], context)
        return

    scenario_name = active_scenario
    assets = grafo.list_assets_by_scenario(str(DB_PATH), scenario_name)
    ttps = mitre.list_ttps()

    build_attack_interface(scenario_name, assets, ttps, context)


if __name__ == "__main__":
    main()
