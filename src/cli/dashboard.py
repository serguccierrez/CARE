"""
Dashboard CLI de CARE/AEGIS: Una sinfonía visual del análisis cibernético.
Transforma datos crudos de amenazas y riesgos en una representación clara y legible,
permitiendo al operador de seguridad comprender de un vistazo el estado de criticidad del sistema.
"""

#==============================================[IMPORTS]==============================================#
import json
import math
from rich.console import Console, Group
from rich.panel import Panel
from rich.text import Text
from rich.progress_bar import ProgressBar
from rich.align import Align
from rich.table import Table
from rich import box
from pathlib import Path


#==============================================[FUNCIONES_AUXILIARES]==============================================#

def load_report_data() -> dict:
    """
    Carga el reporte JSON del análisis de riesgos desde el almacén de datos.
    
    Args:
        Ninguno.
        
    Returns:
        dict: Estructura JSON con threat_vectors, nodes_analysis, global_system_risk y graph_metadata.
    """
    report_path = Path(__file__).parent.parent / "reporting" / "report.json"
    
    with open(report_path, "r", encoding="utf-8") as f:
        return json.load(f)


def load_countermeasures_catalog() -> dict:
    """
    Carga el catalogo de contramedidas para enriquecer la vista de optimizacion.
    """
    countermeasures_path = Path(__file__).parent.parent.parent / "configs" / "countermeasures.json"

    with open(countermeasures_path, "r", encoding="utf-8") as f:
        return json.load(f).get("countermeasures", {})


def extract_report_data(report_data) -> dict:
    """
    Extrae, procesa y sintetiza datos del reporte cibernético en estructuras optimizadas para visualización.
    
    Args:
        report_data (dict): Estructura JSON cruda del reporte.
        
    Returns:
        dict: Diccionario con clave "summary" conteniendo ttps, critical_assets y métricas de riesgo.
    """
    info = {}
    
    # Extraemos vectores de amenaza (TTPs) del reporte
    threat_vectors = report_data.get("threat_vectors", {})
    n_threat_vectors = len(threat_vectors)
    
    # Construimos mapeo de asset_id -> nombre para enriquecimiento de datos
    asset_names = {}
    for block in report_data.get("nodes_analysis", []):
        for asset_id, asset_info in block.items():
            if "node_data" in asset_info and "name" in asset_info["node_data"]:
                asset_names[asset_id] = asset_info["node_data"]["name"]
    
    # Estructuramos datos de TTPs con contexto del activo raíz
    ttps_list = []
    for ttp_id, ttp_data in threat_vectors.items():
        asset_id = ttp_data.get("asset", "N/A")
        asset_name = asset_names.get(asset_id, "Unknown")
        
        ttps_list.append({
            "id": ttp_id,
            "name": ttp_data.get("name", "Unknown"),
            "tactic": ttp_data.get("tactic", "N/A"),
            "asset": asset_id,
            "asset_name": asset_name,
            "confidence": ttp_data.get("confidence", 0),
            "affected_nodes": ttp_data.get("affected_nodes", {})
        })
    
    # Identificamos activos bajo amenaza y sus características
    affected_assets_dict = {}
    nodes_analysis = report_data.get("nodes_analysis", [])
    
    n_affected_assets = len(nodes_analysis[0]) if nodes_analysis else 0
    n_affected_dependencies = n_affected_assets - 1
    total_assets = report_data.get("graph_metadata", {}).get("total_nodes", 1)
    total_dependencies = report_data.get("graph_metadata", {}).get("total_edges", 1)
    
    # Construimos diccionario de activos afectados mapeando sus TTPs asociados
    if nodes_analysis:
        for asset_id, asset_info in nodes_analysis[0].items():
            node_data = asset_info.get("node_data", {})
            criticality = node_data.get("criticality", 0)
            name = node_data.get("name", "Unknown")
            propagation_level = None
            
            # Mapeamos TTPs que impactan este activo
            ttps_affecting = []
            for ttp in ttps_list:
                affected_nodes = ttp.get("affected_nodes", {})
                for level, level_nodes in affected_nodes.items():
                    if asset_id in level_nodes:
                        ttps_affecting.append(ttp["id"])
                        try:
                            current_level = int(level)
                        except (TypeError, ValueError):
                            current_level = 9999

                        if propagation_level is None or current_level < propagation_level:
                            propagation_level = current_level
                        break
            
            # Registramos solo activos bajo amenaza
            if ttps_affecting:
                affected_assets_dict[asset_id] = {
                    "name": name,
                    "criticality": criticality,
                    "propagation_level": propagation_level if propagation_level is not None else 9999,
                    "ttps": ttps_affecting
                }
    
    # Convertimos a lista y ordenamos por nivel de propagacion (de arriba hacia abajo)
    critical_assets = []
    for asset_id, asset_data in affected_assets_dict.items():
        critical_assets.append((asset_id, asset_data))
    
    # Ordenamos primero por nivel de propagacion y, en empate, por criticidad descendente
    for i in range(len(critical_assets)):
        for j in range(i + 1, len(critical_assets)):
            left_level = critical_assets[i][1]["propagation_level"]
            right_level = critical_assets[j][1]["propagation_level"]
            left_criticality = critical_assets[i][1]["criticality"]
            right_criticality = critical_assets[j][1]["criticality"]

            if (
                right_level < left_level
                or (right_level == left_level and right_criticality > left_criticality)
            ):
                critical_assets[i], critical_assets[j] = critical_assets[j], critical_assets[i]
    
    # Limitamos a los 7 activos más críticos para mantener legibilidad
    if len(critical_assets) > 7:
        critical_assets = critical_assets[:7]
    
    # Extraemos riesgo general del sistema
    overall_risk = report_data.get("global_system_risk", {}).get("overall_risk", "N/A")
    initial_compromised = list(dict.fromkeys([ttp.get("asset", "N/A") for ttp in ttps_list]))
    # Compilamos resumen con toda la información procesada
    info["summary"] = {
        "initial_compromised_assets": initial_compromised,
        "vectores_numero": n_threat_vectors,
        "activos_afectados": n_affected_assets,
        "nodos_totales": total_assets,
        "dependencias_afectadas": n_affected_dependencies,
        "dependencias_totales": total_dependencies,
        "riesgo_general": overall_risk,
        "ttps": ttps_list,
        "critical_assets": critical_assets,
        "system_confidentiality_risk": report_data.get("global_system_risk", {}).get("confidentiality_risk", "N/A"),
        "system_integrity_risk": report_data.get("global_system_risk", {}).get("integrity_risk", "N/A"),
        "system_availability_risk": report_data.get("global_system_risk", {}).get("availability_risk", "N/A"),
        "analysis_timestamp": report_data.get("metadata", {}).get("timestamp", "N/A"),
    }
    return info



def bar_risk_color(value) -> str:
    """
    Mapea un valor numérico de riesgo a color para visualización cromática.
    
    Args:
        value (float): Valor de riesgo entre 0 y 10.
        
    Returns:
        str: Código de color Rich (green, yellow, orange3 o red).
    """
    if value >= 0.0 and value < 2.5:
        return "green"
    elif value >= 2.5 and value < 5.0:
        return "yellow"
    elif value >= 5.0 and value < 7.5:
        return "orange3"
    elif value >= 7.5 and value <= 10.0:
        return "red"
    return "unknown"


def confidence_color(value) -> str:
    """
    Mapea probabilidad de amenaza a color para análisis de TTPs.
    
    Args:
        value (float): Probabilidad entre 0 y 1.
        
    Returns:
        str: Código de color Rich escalado desde verde (bajo) a rojo (crítico).
    """
    if value >= 0.0 and value < 0.5:
        return "green"
    elif value >= 0.5 and value < 0.6:
        return "yellow"
    elif value >= 0.6 and value <= 0.8:
        return "orange3"
    elif value > 0.8 and value <= 1.0:
        return "red"
    return "unknown"


#==============================================[CONSOLE_Y_RENDERIZADO]==============================================#

console = Console()  # Motor de renderizado terminal


def render_header(info, optimization_mode=False, context=None) -> Panel:
    """
    Renderiza el encabezado visual del dashboard: CARE/AEGIS.
    
    Args:
        info (dict): Estructura procesada con los datos del dashboard.
        
    Returns:
        Panel: Componente gráfico con título, subtítulo y timestamp.
    """
    analysis_timestamp = info["summary"].get("analysis_timestamp", "N/A")
    context = context or {}
    scenario_name = context.get("active_scenario") or "N/A"

    header_text = Text(justify="center")
    header_text.append("CARE / AEGIS\n", style="bold cyan")
    header_text.append("Cyber Action Recommendation Engine\n", style="dim")
    if optimization_mode:
        header_text.append("Optimization Decision View\n", style="bold green")
    header_text.append(f"Scenario: {scenario_name}\n", style="dim")
    header_text.append(f"Last analysis: {analysis_timestamp}", style="dim white")

    header = Panel(
        Align.center(header_text, vertical="middle"),
        border_style="cyan",
        box=box.ROUNDED
    )

    return header


def render_summary_panel(info, panel_height=None) -> Panel:
    """
    Compila resumen operativo del incidente: activos comprometidos, vectores detectados y propagación.
    
    Args:
        info (dict): Estructura procesada con datos de análisis (summary).
        
    Returns:
        Panel: Visualización formateada del resumen operativo.
    """
    threat_vectors = ", ".join([ttp['id'] for ttp in info["summary"]["ttps"]])
    initial_assets = ", ".join(info["summary"]["initial_compromised_assets"])
    
    summary_text = f"""
[bold]Initial Compromised Assets:[/bold] {initial_assets}
[bold]Threat Vectors:[/bold] {threat_vectors}
[bold]Total Threat Vectors:[/bold] {info["summary"]["vectores_numero"]}
[bold]Affected Assets:[/bold] {info["summary"]["activos_afectados"]} / {info["summary"]["nodos_totales"]}
[bold]Affected Dependencies:[/bold] {info["summary"]["dependencias_afectadas"]} / {info["summary"]["dependencias_totales"]}
[bold]Percentage of Network Affected:[/bold] {(info["summary"]["activos_afectados"] / info["summary"]["nodos_totales"])*100:.1f}%
"""

    panel = Panel(
        Align.center(summary_text, vertical="middle"),
        title="Operational Summary",
        border_style="yellow",
        height=panel_height,
    )

    return panel


def render_risk_panel(info, panel_height=None) -> Panel:
    """
    Visualiza el perfil de riesgo del sistema desglosado en las tres dimensiones CIA.
    
    Utiliza barras de progreso coloreadas para comunicar de forma inmediata la severidad
    de cada dimensión y el riesgo general acumulado.
    
    Args:
        info (dict): Estructura procesada con métricas de riesgo global y por CIA.
        
    Returns:
        Panel: Tabla con barras de progreso coloreadas según severidad.
    """
    risk_value = round(info["summary"]["riesgo_general"], 2)
    confidentiality_risk = round(info["summary"]["system_confidentiality_risk"], 2) 
    integrity_risk = round(info["summary"]["system_integrity_risk"], 2)
    availability_risk = round(info["summary"]["system_availability_risk"], 2)

    bar = ProgressBar(total=10, completed=risk_value, complete_style=bar_risk_color(risk_value))
    bar_confidentiality = ProgressBar(total=10, completed=confidentiality_risk, complete_style=bar_risk_color(confidentiality_risk))
    bar_integrity = ProgressBar(total=10, completed=integrity_risk, complete_style=bar_risk_color(integrity_risk))
    bar_availability = ProgressBar(total=10, completed=availability_risk, complete_style=bar_risk_color(availability_risk))

    # Tabla sin bordes para integración visual fluida
    table = Table(show_header=False, show_footer=False, box=None, padding=(0, 1))
    table.add_column("Label", style="bold", min_width=24, ratio=4)
    table.add_column("Value", width=8, justify="right")
    table.add_column("Bar", min_width=20, ratio=5)

    table.add_row("OVERALL SYSTEM RISK:", f"{risk_value}/10", bar)
    table.add_row("", "", "")  # Separación visual
    table.add_row("     • Confidentiality Risk:", f"{confidentiality_risk}/10", bar_confidentiality)
    table.add_row("     • Integrity Risk:", f"{integrity_risk}/10", bar_integrity)
    table.add_row("     • Availability Risk:", f"{availability_risk}/10", bar_availability)

    panel = Panel(
        Align.center(table, vertical="middle"),
        title="Global Risk Level",
        border_style="red",
        padding=(1, 1),
        height=panel_height

    )

    return panel


def render_critical_assets_table(info, panel_height=None) -> Panel:
    """
    Cataloga los activos más críticos bajo amenaza, ordenados por severidad de impacto.
    
    Limita a los 7 más relevantes para mantener legibilidad sin sacrificar contexto.
    Muestra qué vectores de ataque impactan cada activo.
    
    Args:
        info (dict): Estructura con lista de activos críticos ordenada.
        
    Returns:
        Panel: Tabla interactiva con activos y sus vectores de amenaza asociados.
    """
    critical_assets = info["summary"]["critical_assets"]
    
    table = Table(show_header=True, header_style="bold", expand=True)
    table.add_column("ASSET ID", style="cyan", min_width=8, justify="center", no_wrap=True)
    table.add_column("NAME", style="green", min_width=12, justify="center", overflow="fold")
    table.add_column("PROP LEVEL", style="yellow", min_width=11, justify="center", no_wrap=True)
    table.add_column("AFFECTED BY TTP", style="magenta", min_width=12, justify="center", overflow="fold")

    for asset_id, asset_data in critical_assets:
        propagation_level = asset_data["propagation_level"]
        name = asset_data["name"]
        ttps_str = ", ".join(asset_data["ttps"])
        
        table.add_row(asset_id, name, str(propagation_level), ttps_str)
    
    panel = Panel(
        Align.center(table, vertical="middle"),
        title="Affected Assets by Propagation Order",
        padding=(0, 0),
        box=box.SIMPLE,
        expand=True,
        height=panel_height,
    )
    
    return panel


def render_ttps_table(info, panel_height=None) -> Panel:
    """
    Tabula el catálogo completo de vectores de amenaza (TTPs) detectados.
    
    Enumera técnicas MITRE ATT&CK por identificador, tactic, activo raíz y probabilidad
    de ocurrencia. El color de probabilidad comunica certidumbre del impacto.
    
    Args:
        info (dict): Estructura con lista completa de TTPs procesados.
        
    Returns:
        Panel: Tabla extendida con TTPs y sus atributos descriptivos.
    """
    table = Table(expand=True)
    table.add_column("TTP ID", style="cyan", min_width=8, justify="center", no_wrap=True)
    table.add_column("Name", style="green", justify="center", min_width=12, overflow="fold")
    table.add_column("Tactic", style="yellow", min_width=12, justify="center", overflow="fold")
    table.add_column("Root Asset", style="blue", min_width=18, justify="center", overflow="fold")
    table.add_column("P(Threat)", width=10, justify="center", no_wrap=True)

    ttps = info["summary"]["ttps"]
    for ttp in ttps:
        root_asset = ttp.get("asset", "N/A")
        confidence = ttp.get("confidence", 0)
        confidence_str = f"{confidence*100:.1f}%"
        
        table.add_row(
            ttp["id"],
            ttp["name"][:28],
            ttp["tactic"][:30],
            root_asset + ' (' + ttp.get("asset_name", "Unknown") + ')',
            Text(confidence_str, style=f"bold {confidence_color(confidence)}")
        )
    
    panel = Panel(
        Align.center(table, vertical="middle"),
        title="TTP Analysis",
        padding=(0, 0),
        expand=True,
        box=box.SIMPLE,
        height=panel_height,
    )

    return panel


def render_optimizations_ask_panel(context=None) -> Panel:
    """
    Panel instructivo que guía al operador hacia la fase de optimización.
    
    Presenta las opciones de objetivos de protección disponibles y facilita
    la transición del análisis a la recomendación de contramedidas.
    
    Args:
        Ninguno.
        
    Returns:
        Panel: Guía interactiva con opciones y comando sugerido.
    """
    context = context or {}
    objective = context.get("optimization_objective") or "Not configured"
    budget = context.get("optimization_budget")
    time_limit = context.get("optimization_time")

    budget_text = f"{budget:.0f} €" if isinstance(budget, (int, float)) else "Not configured"
    time_text = f"{time_limit:.1f} h" if isinstance(time_limit, (int, float)) else "Not configured"

    optimization_text = f"""[bold]Current config:[/bold] objective={objective} | budget={budget_text} | time={time_text}

[bold]Objectives:[/bold]
  [bold]global[/bold]           Overall risk
  [bold]confidentiality[/bold]  Data exposure / exfiltration
  [bold]integrity[/bold]        Unauthorized modification
  [bold]availability[/bold]     Downtime / disruption

[bold]Commands:[/bold]
  python -m src.cli.care optimize config --objective <objective> --budget <value> --time <hours>
  python -m src.cli.care optimize run
"""

    panel = Panel(
            optimization_text,
            title="[OPTIMIZATION OBJECTIVE]",
            border_style="green",
            padding=(1, 2)
    )
 
    return panel


def get_report_assets(report_data) -> dict:
    """
    Devuelve los activos indexados por asset_id para reutilizarlos en el dashboard.
    """
    assets = {}

    for block in report_data.get("nodes_analysis", []):
        for asset_id, asset_info in block.items():
            assets[asset_id] = asset_info

    return assets


def extract_optimization_data(report_data, optimization_results, context=None) -> dict:
    """
    Prepara los datos minimos necesarios para representar resultados de optimizacion.
    """
    context = context or {}

    if not optimization_results:
        return {"summary": {"asset_rows": []}}

    selected_objective = context.get("optimization_objective")
    objective = selected_objective if selected_objective in optimization_results else next(iter(optimization_results.keys()))
    solution = optimization_results.get(objective, {})

    report_assets = get_report_assets(report_data)
    countermeasures_catalog = load_countermeasures_catalog()
    selected_assets = []
    countermeasures_by_asset = {}

    baseline_key_by_objective = {
        "global": "asset_average_risk",
        "confidentiality": "asset_confidentiality_risk",
        "integrity": "asset_integrity_risk",
        "availability": "asset_availability_risk",
    }
    solution_key_by_objective = {
        "global": "risk_total",
        "confidentiality": "asset_risk_C",
        "integrity": "asset_risk_I",
        "availability": "asset_risk_A",
    }

    baseline_metric = baseline_key_by_objective.get(objective, "asset_average_risk")
    optimized_metric = solution_key_by_objective.get(objective, "risk_total")

    for asset_id, decision in solution.get("assets_decisions", {}).items():
        asset_info = report_assets.get(asset_id, {})
        before_risk = float(asset_info.get(baseline_metric, 0.0) or 0.0)
        after_risk = float(decision.get(optimized_metric, 0.0) or 0.0)
        delta_risk = after_risk - before_risk

        selected_asset = {
            "asset_id": asset_id,
            "asset_name": asset_info.get("node_data", {}).get("name", "Unknown"),
            "countermeasure": decision.get("countermeasure", "none"),
            "before_risk": before_risk,
            "after_risk": after_risk,
            "delta_risk": delta_risk,
            "cost": float(decision.get("cost", 0.0) or 0.0),
            "time_hours": float(decision.get("time_hours", 0.0) or 0.0),
        }
        selected_assets.append(selected_asset)
        cm_id = selected_asset["countermeasure"]
        cm_info = countermeasures_catalog.get(cm_id, {})
        if cm_id not in countermeasures_by_asset:
            countermeasures_by_asset[cm_id] = {
                "id": cm_id,
                "name": cm_info.get("name", cm_id),
                "assets": [],
            }
        countermeasures_by_asset[cm_id]["assets"].append(selected_asset["asset_id"])

    selected_assets.sort(key=lambda asset: asset["delta_risk"])

    system_risk_by_objective = {
        "global": float(report_data.get("global_system_risk", {}).get("overall_risk", 0.0) or 0.0),
        "confidentiality": float(report_data.get("global_system_risk", {}).get("confidentiality_risk", 0.0) or 0.0),
        "integrity": float(report_data.get("global_system_risk", {}).get("integrity_risk", 0.0) or 0.0),
        "availability": float(report_data.get("global_system_risk", {}).get("availability_risk", 0.0) or 0.0),
    }

    total_criticality = float(solution.get("total_criticality", 0.0) or 0.0)
    if total_criticality:
        optimized_system_risks = {
            "global": sum(float(decision.get("risk_total", 0.0) or 0.0) * float(decision.get("criticality", 0.0) or 0.0) for decision in solution.get("assets_decisions", {}).values()) / total_criticality,
            "confidentiality": sum(float(decision.get("asset_risk_C", 0.0) or 0.0) * float(decision.get("criticality", 0.0) or 0.0) for decision in solution.get("assets_decisions", {}).values()) / total_criticality,
            "integrity": sum(float(decision.get("asset_risk_I", 0.0) or 0.0) * float(decision.get("criticality", 0.0) or 0.0) for decision in solution.get("assets_decisions", {}).values()) / total_criticality,
            "availability": sum(float(decision.get("asset_risk_A", 0.0) or 0.0) * float(decision.get("criticality", 0.0) or 0.0) for decision in solution.get("assets_decisions", {}).values()) / total_criticality,
        }
    else:
        optimized_system_risks = dict(system_risk_by_objective)

    objective_before = system_risk_by_objective.get(objective, 0.0)
    objective_after = optimized_system_risks.get(objective, objective_before)

    info = {
        "summary": {
            "analysis_timestamp": report_data.get("metadata", {}).get("timestamp", "N/A"),
            "objective": objective,
            "status": solution.get("status", "Unknown"),
            "objective_before": objective_before,
            "objective_after": objective_after,
            "objective_delta": objective_after - objective_before,
            "budget": float(solution.get("budget", 0.0) or 0.0),
            "total_cost": float(solution.get("total_cost", 0.0) or 0.0),
            "time_limit": float(context.get("optimization_time", 0.0) or 0.0),
            "asset_rows": selected_assets,
            "grouped_countermeasures": countermeasures_by_asset,
            "assets_with_new_cm": len([asset for asset in selected_assets if asset["countermeasure"] != "none"]),
            "assets_without_changes": len([asset for asset in selected_assets if asset["countermeasure"] == "none"]),
            "system_risk_before": system_risk_by_objective,
            "system_risk_after": optimized_system_risks,
        }
    }

    return info


def optimization_delta_style(delta: float) -> str:
    """
    Verde si reduce riesgo, rojo si empeora y amarillo si no cambia.
    """
    if delta < 0:
        return "bold green"
    if delta > 0:
        return "bold red"
    return "bold yellow"


def format_objective_label(objective: str) -> str:
    labels = {
        "global": "Overall System Risk",
        "confidentiality": "Confidentiality Risk",
        "integrity": "Integrity Risk",
        "availability": "Availability Risk",
    }
    return labels.get(objective, "Optimization Objective")


def estimate_wrapped_lines(text: str, width: int) -> int:
    """
    Estima cuantas lineas ocupara un texto al envolverlo en una anchura dada.
    """
    if not text:
        return 1
    safe_width = max(width, 1)
    return max(1, math.ceil(len(text) / safe_width))


def optimization_top_panel_height(info) -> int:
    """
    Ajusta la altura del resumen superior para evitar huecos o recortes.
    """
    summary = info["summary"]
    budget_percent = (summary["total_cost"] / summary["budget"] * 100) if summary["budget"] else 0.0
    summary_lines = 6
    risk_lines = 7
    base_height = 6

    if budget_percent >= 100:
        summary_lines += 1

    return base_height + max(summary_lines, risk_lines)


def optimization_analysis_panel_height(info, console_width: int) -> int:
    """
    Calcula la altura necesaria para las tablas de optimizacion segun filas visibles
    y el posible wrapping del agrupado de despliegue.
    """
    asset_rows = info["summary"]["asset_rows"][:8]
    grouped_countermeasures = info["summary"]["grouped_countermeasures"]

    asset_name_width = 14 if console_width >= 170 else 12
    asset_cm_width = 10
    asset_table_lines = 3
    for row in asset_rows:
        name_lines = estimate_wrapped_lines(row["asset_name"], asset_name_width)
        cm_lines = estimate_wrapped_lines(row["countermeasure"], asset_cm_width)
        asset_table_lines += max(name_lines, cm_lines, 1)

    if console_width >= 170:
        name_column_width = 28
        assets_column_width = max(int(console_width * 0.18), 28)
    else:
        name_column_width = 24
        assets_column_width = max(console_width - 24, 24)

    grouping_lines = 3
    for cm_data in sorted(grouped_countermeasures.values(), key=lambda item: (-len(item["assets"]), item["id"])):
        asset_text = ", ".join(cm_data["assets"])
        grouping_lines += max(
            estimate_wrapped_lines(cm_data["name"], name_column_width),
            estimate_wrapped_lines(asset_text, assets_column_width),
        )

    base_height = 5
    return base_height + max(asset_table_lines, grouping_lines)


def render_optimization_summary_panel(info, panel_height=None) -> Panel:
    """
    Resume el resultado operativo de la optimizacion.
    """
    summary = info["summary"]
    budget_percent = (summary["total_cost"] / summary["budget"] * 100) if summary["budget"] else 0.0

    summary_text = f"""
[bold]Target Risk:[/bold] {format_objective_label(summary["objective"])}
[bold]Solver Status:[/bold] {summary["status"]}
[bold]Assets With Selected CM:[/bold] {summary["assets_with_new_cm"]}
[bold]Assets Kept in Baseline:[/bold] {summary["assets_without_changes"]}
[bold]Budget Consumption:[/bold] {summary["total_cost"]:.0f} / {summary["budget"]:.0f} ({budget_percent:.1f}%)
[bold]Deployment Time Limit:[/bold] {summary["time_limit"]:.1f} h
"""

    panel = Panel(
        Align.center(summary_text, vertical="middle"),
        title="Optimization Summary",
        border_style="yellow",
        height=panel_height,
    )

    return panel


def render_optimization_risk_panel(info, panel_height=None) -> Panel:
    """
    Muestra comparativa del riesgo objetivo antes y despues de optimizar.
    """
    summary = info["summary"]
    objective = summary["objective"]
    before_risk = round(summary["objective_before"], 2)
    after_risk = round(summary["objective_after"], 2)
    delta = summary["objective_delta"]
    before_risk_bar = ProgressBar(total=10, completed=before_risk, complete_style=bar_risk_color(before_risk))
    risk_bar = ProgressBar(total=10, completed=after_risk, complete_style=bar_risk_color(after_risk))

    labels = {
        "global": "OVERALL",
        "confidentiality": "CONFIDENTIALITY",
        "integrity": "INTEGRITY",
        "availability": "AVAILABILITY",
    }

    table = Table(show_header=False, show_footer=False, box=None, padding=(0, 1))
    table.add_column("Label", style="bold", min_width=22, ratio=4)
    table.add_column("Value", width=12, justify="right")
    table.add_column("Bar", min_width=20, ratio=5)

    target_label = labels.get(objective, objective.upper())

    table.add_row(f"TARGET {target_label} / BEFORE:", f"{before_risk}/10", before_risk_bar)
    table.add_row(f"TARGET {target_label} / AFTER:", f"{after_risk}/10", risk_bar)
    table.add_row("DELTA:", Text(f"{delta:+.2f}", style=optimization_delta_style(delta)), "")
    table.add_row("", "", "")

    for key in ["global", "confidentiality", "integrity", "availability"]:
        if key == objective:
            continue
        before_value = summary["system_risk_before"].get(key, 0.0)
        after_value = summary["system_risk_after"].get(key, 0.0)
        delta_value = after_value - before_value
        table.add_row(
            f"  {labels[key]} / BACKGROUND:",
            f"{before_value:.2f} -> {after_value:.2f}",
            Text(f"{delta_value:+.2f}", style=optimization_delta_style(delta_value))
        )

    panel = Panel(
        Align.center(table, vertical="middle"),
        title="Risk Reduction",
        border_style="red",
        padding=(1, 1),
        height=panel_height
    )

    return panel


def render_optimization_assets_table(info, panel_height=None) -> Panel:
    """
    Tabla principal de contramedida seleccionada por activo.
    """
    table = Table(show_header=True, header_style="bold", expand=True)
    table.add_column("ASSET ID", style="cyan", min_width=8, justify="center", no_wrap=True)
    table.add_column("NAME", style="green", min_width=12, justify="center", overflow="fold")
    table.add_column("CM", style="magenta", min_width=10, justify="center", overflow="fold")
    table.add_column("BEFORE", style="yellow", min_width=8, justify="center", no_wrap=True)
    table.add_column("AFTER", style="yellow", min_width=8, justify="center", no_wrap=True)
    table.add_column("DELTA", style="blue", min_width=8, justify="center", no_wrap=True)

    rows = info["summary"]["asset_rows"]
    for row in rows[:8]:
        table.add_row(
            row["asset_id"],
            row["asset_name"],
            row["countermeasure"],
            f"{row['before_risk']:.2f}",
            f"{row['after_risk']:.2f}",
            Text(f"{row['delta_risk']:+.2f}", style=optimization_delta_style(row["delta_risk"]))
        )

    panel = Panel(
        Align.center(table, vertical="middle"),
        title="Recommended Countermeasures by Asset",
        padding=(0, 0),
        box=box.SIMPLE,
        expand=True,
        height=panel_height,
    )

    return panel


def render_countermeasure_distribution_panel(info, panel_height=None) -> Panel:
    """
    Presenta las contramedidas seleccionadas en un formato mas legible.
    """
    table = Table(show_header=True, header_style="bold", expand=True, box=box.SIMPLE)
    table.add_column("CM", style="magenta", min_width=8, justify="center", no_wrap=True)
    table.add_column("COUNTERMEASURE", style="yellow", min_width=24, justify="left", overflow="fold")
    table.add_column("ASSETS", style="green", min_width=14, justify="center", no_wrap=True)

    grouped_countermeasures = info["summary"]["grouped_countermeasures"]
    for cm_data in sorted(grouped_countermeasures.values(), key=lambda item: (-len(item["assets"]), item["id"])):
        assets = cm_data["assets"]
        table.add_row(
            cm_data["id"],
            cm_data["name"],
            f"{len(assets)} asset(s)",
        )

    panel = Panel(
        Align.center(table, vertical="middle"),
        title="Selected Countermeasures",
        padding=(0, 0),
        box=box.SIMPLE,
        expand=True,
        height=panel_height,
    )

    return panel


def build_dashboard(info, optimization_mode=False, context=None):
    """
    Ensambla todos los componentes visuales en un layout jerárquico coherente.
    
    Organiza la información en tres niveles verticales: encabezado, análisis operativo/riesgos,
    análisis detallado (activos y TTPs), y guía de optimización. Los tamaños se ajustan
    dinámicamente según volumen de datos.
    
    Args:
        info (dict): Estructura compilada con summary completo del análisis.
        
    Returns:
        Layout: Árbol de componentes Rich listo para renderizar.
    """
    console_width = console.size.width
    if optimization_mode:
        top_panel_height = optimization_top_panel_height(info)
        analysis_panel_height = optimization_analysis_panel_height(info, console_width)
        top_sections = [
            render_optimization_summary_panel(info, panel_height=top_panel_height),
            render_optimization_risk_panel(info, panel_height=top_panel_height)
        ]
        analysis_sections = [
            render_optimization_assets_table(info, panel_height=analysis_panel_height),
            render_countermeasure_distribution_panel(info, panel_height=analysis_panel_height)
        ]
    else:
        top_panel_height = 10
        n_critical_assets = len(info["summary"]["critical_assets"])
        n_ttps = len(info["summary"]["ttps"])
        analysis_panel_height = 11 + max(n_critical_assets, n_ttps, 1)
        top_sections = [
            render_summary_panel(info, panel_height=top_panel_height),
            render_risk_panel(info, panel_height=top_panel_height)
        ]
        analysis_sections = [
            render_critical_assets_table(info, panel_height=analysis_panel_height),
            render_ttps_table(info, panel_height=analysis_panel_height)
        ]

    # Ensamblamos la capa superior del dashboard con Layout para repartir el espacio simétricamente
    if console_width >= 120:
        top_content = Table.grid(expand=True)
        top_content.add_column(ratio=1)
        top_content.add_column(ratio=1)
        top_content.add_row(*top_sections)
    else:
        top_content = Group(*top_sections)

    # Construimos la zona analítica manteniendo proporción visual entre activos críticos y TTPs
    if console_width >= 170:
        analysis_content = Table.grid(expand=True)
        analysis_content.add_column(ratio=6)
        analysis_content.add_column(ratio=7)
        analysis_content.add_row(*analysis_sections)
    else:
        analysis_content = Group(*analysis_sections)

    analysis_panel = Panel(
        analysis_content,
        title="[OPTIMIZATION RESULTS]" if optimization_mode else "[ANALYSIS]",
        border_style="blue",
        expand=True,
    )

    if optimization_mode:
        return Group(
            render_header(info, optimization_mode=True, context=context),
            top_content,
            analysis_panel,
        )

    return Group(
        render_header(info, context=context),
        top_content,
        analysis_panel,
        render_optimizations_ask_panel(context),
    )


def main(show_optimization=False, optimization_results=None, context=None):
    """
    Punto de entrada principal: orquesta carga, extracción y renderizado del dashboard.
    
    Ejecuta la pipeline de transformación de datos crudos a visualización terminal.
    
    Args:
        Ninguno.
        
    Returns:
        Ninguno. Efecto secundario: imprime dashboard a stdout.
    """
    report_data = load_report_data()
    context = context or {}

    if show_optimization and optimization_results:
        info = extract_optimization_data(report_data, optimization_results, context)
        dashboard = build_dashboard(info, optimization_mode=True, context=context)
    else:
        info = extract_report_data(report_data)
        dashboard = build_dashboard(info, context=context)

    console.print(dashboard)

#==============================================[ENTRY POINT]==============================================#
if __name__ == "__main__":
    main()
