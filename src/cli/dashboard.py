"""
Dashboard CLI de CARE/AEGIS: Una sinfonía visual del análisis cibernético.
Transforma datos crudos de amenazas y riesgos en una representación clara y legible,
permitiendo al operador de seguridad comprender de un vistazo el estado de criticidad del sistema.
"""

#==============================================[IMPORTS]==============================================#
import json
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





def analysis_row_height(info) -> int:
    """
    Calcula la altura conjunta del bloque analítico en función de la tabla con más filas.
    
    Se toma como referencia el mayor número de registros entre activos críticos y TTPs
    para que ambos paneles laterales tengan la misma altura y el contenedor quede ajustado,
    sin exceso de espacio vacío ni recortes visuales.
    
    Args:
        info (dict): Estructura procesada con los datos del dashboard.
        
    Returns:
        int: Altura recomendada para ambos paneles del bloque de análisis.
    """
    n_critical_assets = len(info["summary"]["critical_assets"])
    n_ttps = len(info["summary"]["ttps"])
    max_rows = max(n_critical_assets, n_ttps, 1)

    return 7 + max_rows


def render_header() -> Panel:
    """
    Renderiza el encabezado visual del dashboard: CARE/AEGIS.
    
    Args:
        Ninguno.
        
    Returns:
        Panel: Componente gráfico con título y subtítulo centrado.
    """
    header_text = Text(justify="center")
    header_text.append("CARE / AEGIS\n", style="bold cyan")
    header_text.append("Cyber Action Recommendation Engine\n", style="dim")
    header_text.append(
        f"Last analysis: {info_timestamp_placeholder}",
        style="dim white",
    )

    header = Panel(
        Align.center(header_text, vertical="middle"),
        border_style="cyan",
        box=box.ROUNDED
    )

    return header


def render_header(info) -> Panel:
    """
    Renderiza el encabezado visual del dashboard: CARE/AEGIS.
    
    Args:
        info (dict): Estructura procesada con los datos del dashboard.
        
    Returns:
        Panel: Componente grÃ¡fico con tÃ­tulo, subtÃ­tulo y timestamp.
    """
    analysis_timestamp = info["summary"].get("analysis_timestamp", "N/A")

    header_text = Text(justify="center")
    header_text.append("CARE / AEGIS\n", style="bold cyan")
    header_text.append("Cyber Action Recommendation Engine\n", style="dim")
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


def render_optimizations_ask_panel() -> Panel:
    """
    Panel instructivo que guía al operador hacia la fase de optimización.
    
    Presenta las opciones de objetivos de protección disponibles y facilita
    la transición del análisis a la recomendación de contramedidas.
    
    Args:
        Ninguno.
        
    Returns:
        Panel: Guía interactiva con opciones y comando sugerido.
    """
    optimization_text = """[bold]Select protection objective:[/bold]

  [bold]<global>            Minimize overall system risk
                            -> Balanced reduction across confidentiality, integrity, availability

  [bold]<confidentiality>   Protect sensitive data
                            -> Reduce exposure and data exfiltration risk

  [bold]<integrity>         Protect data integrity
                            -> Prevent unauthorized modification and tampering

  [bold]<availability>      Ensure service availability
                            -> Minimize disruptions and downtime

[bold]Command:[/bold]
  python care.py optimize [dim]--objective <global | confidentiality | integrity | availability>
"""

    panel = Panel(
            optimization_text,
            title="[OPTIMIZATION OBJECTIVE]",
            border_style="green",
            padding=(1, 2)
    )
 
    return panel


def build_dashboard(info):
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
    top_panel_height = 10
    analysis_panel_height = analysis_row_height(info)

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
        title="[ANALYSIS]",
        border_style="blue",
        expand=True,
    )

    return Group(
        render_header(info),
        top_content,
        analysis_panel,
        render_optimizations_ask_panel(),
    )


def main():
    """
    Punto de entrada principal: orquesta carga, extracción y renderizado del dashboard.
    
    Ejecuta la pipeline de transformación de datos crudos a visualización terminal.
    
    Args:
        Ninguno.
        
    Returns:
        Ninguno. Efecto secundario: imprime dashboard a stdout.
    """
    info = extract_report_data(load_report_data())
    dashboard = build_dashboard(info)
    console.print(dashboard)

#==============================================[ENTRY POINT]==============================================#
if __name__ == "__main__":
    main()
