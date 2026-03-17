#==============================================[IMPORTS]==============================================#
import json
from rich.console import Console, Group
from rich.panel import Panel
from rich.columns import Columns
from rich.layout import Layout
from rich.text import Text
from rich.progress_bar import ProgressBar
from rich.align import Align
from rich.table import Table
from rich import box


from pathlib import Path


#==============================================[AUXILIAR]==============================================#
def load_report_data():
    report_path = Path(__file__).parent.parent / "reporting" / "report.json"
    
    with open(report_path, "r", encoding="utf-8") as f:
        return json.load(f)
    

def extract_report_data(report_data):
    info = {}
    
    # === THREAT VECTORS ===
    threat_vectors = report_data.get("threat_vectors", {})
    n_threat_vectors = len(threat_vectors)
    
    # Crear un diccionario de asset_id -> asset_name desde nodes_analysis
    asset_names = {}
    for block in report_data.get("nodes_analysis", []):
        for asset_id, asset_info in block.items():
            if "node_data" in asset_info and "name" in asset_info["node_data"]:
                asset_names[asset_id] = asset_info["node_data"]["name"]
    
    # Extraer datos de TTPs de forma estructurada
    ttps_list = []
    for ttp_id, ttp_data in threat_vectors.items():
        asset_id = ttp_data.get("asset", "N/A")
        asset_name = asset_names.get(asset_id, "Unknown")  # Buscar el nombre en el diccionario
        
        ttps_list.append({
            "id": ttp_id,
            "name": ttp_data.get("name", "Unknown"),
            "tactic": ttp_data.get("tactic", "N/A"),
            "asset": asset_id,
            "asset_name": asset_name,  # Nuevo campo
            "confidence": ttp_data.get("confidence", 0),
            "affected_nodes": ttp_data.get("affected_nodes", {})
        })
    
    # === NODES ANALYSIS ===
    nodes_analysis = report_data.get("nodes_analysis", [])
    n_affected_assets = len(nodes_analysis[0]) if nodes_analysis else 0
    n_affected_dependencies = n_affected_assets - 1
    total_assets = report_data.get("graph_metadata", {}).get("total_nodes", 1)  # Evitar división por cero
    
    overall_risk = report_data.get("global_system_risk", {}).get("overall_risk", "N/A")
    
    print(report_data.get("global_system_risk", {}).get("confidentiality_risk", "N/A"))
    # Calcular initial_compromised_assets antes de crear info["summary"]
    initial_compromised = [ttp.get("asset", "N/A") for ttp in ttps_list]
    
    info["summary"] = {
        "initial_compromised_assets": initial_compromised,
        "vectores_numero": n_threat_vectors,
        "activos_afectados": n_affected_assets,
        "nodos_totales": total_assets,
        "dependencias_afectadas": n_affected_dependencies,
        "riesgo_general": overall_risk,
        "ttps": ttps_list,
        "system_confidentiality_risk": report_data.get("global_system_risk", {}).get("confidentiality_risk", "N/A"),
        "system_integrity_risk": report_data.get("global_system_risk", {}).get("integrity_risk", "N/A"),
        "system_availability_risk": report_data.get("global_system_risk", {}).get("availability_risk", "N/A"),
    }
    return info



def bar_risk_color(value):
    if value >= 0.0 and value < 2.5:
        return "green"      # Bajo riesgo (0-2.5)
    elif value >= 2.5 and value < 5.0:
        return "yellow"     # Riesgo medio (2.5-5)
    elif value >= 5.0 and value < 7.5:
        return "orange"     # Riesgo alto (5-7.5)
    elif value >= 7.5 and value <= 10.0:
        return "red"        # Riesgo crítico (7.5-10)
    return "unknown"

def confidence_color(value):
    if value >= 0.0 and value < 0.5:
        return "green"        # Baja confianza (0-0.5)
    elif value >= 0.5 and value < 0.8:
        return "yellow"     # Confianza media (0.5-0.8)
    elif value >= 0.8 and value <= 1.0:
        return "red"      # Alta confianza (0.8-1)
    return "unknown"

#==============================================[DASHBOARD]=============================================#
console = Console() # Creamos un objeto Console para imprimir en la terminal

#==============================[FUNCIONES DE RENDERIZADO]==============================================#
def render_header():
    header_text = Text(justify="center")
    header_text.append("CARE / AEGIS\n", style="bold cyan")
    header_text.append("Cyber Action Recommendation Engine", style="dim")

    header = Panel(
        Align.center(header_text, vertical="middle"),
        border_style="cyan",
        box=box.ROUNDED
        
    )

    return header

def render_summary_panel(info):
    threat_vectors = ", ".join([ttp['id'] for ttp in info["summary"]["ttps"]])
    
    initial_assets = ", ".join(info["summary"]["initial_compromised_assets"])
    
    summary_text = f"""
[bold]Initial Compromised Asset:[/bold] {initial_assets}
[bold]Threat Vector:[/bold] {threat_vectors}
[bold]Total Threat Vectors:[/bold] {info["summary"]["vectores_numero"]}
[bold]Affected Assets:[/bold] {info["summary"]["activos_afectados"]}
[bold]Affected Dependencies:[/bold] {info["summary"]["dependencias_afectadas"]}
[bold]Percentage of Network Affected:[/bold] {(info["summary"]["activos_afectados"] / info["summary"]["nodos_totales"])*100:.1f}%
"""

    panel = Panel(
        Align.center(summary_text),
        title="Operational Summary",
        border_style="yellow",
    )

    return panel


def render_risk_panel(info):

    risk_value = round(info["summary"]["riesgo_general"], 2)

    confidentiality_risk = round(info["summary"]["system_confidentiality_risk"], 2) 
    integrity_risk = round(info["summary"]["system_integrity_risk"], 2)
    availability_risk = round(info["summary"]["system_availability_risk"], 2
    )

    bar = ProgressBar(total=10, completed=risk_value, complete_style=bar_risk_color(risk_value))
    bar_confidentiality = ProgressBar(total=10, completed=confidentiality_risk, complete_style=bar_risk_color(confidentiality_risk))
    bar_integrity = ProgressBar(total=10, completed=integrity_risk, complete_style=bar_risk_color(integrity_risk))
    bar_availability = ProgressBar(total=10, completed=availability_risk, complete_style=bar_risk_color(availability_risk))

    # Crear tabla sin bordes
    table = Table(show_header=False, show_footer=False, box=None, padding=(0, 1))
    table.add_column("Label", style="bold", width=25)
    table.add_column("Value", width=8, justify="right")
    table.add_column("Bar", width=35)

    table.add_row("Overall System Risk:", f"{risk_value}/10", bar)
    table.add_row("Confidentiality Risk:", f"{confidentiality_risk}/10", bar_confidentiality)
    table.add_row("Integrity Risk:", f"{integrity_risk}/10", bar_integrity)
    table.add_row("Availability Risk:", f"{availability_risk}/10", bar_availability)

    panel = Panel(
        Align.center(table),
        title="Global Risk Level",
        border_style="red",
        padding=(1, 1)
    )

    return panel


def render_ttps_table(info):
    """Renderiza tabla con TTP | Nombre | Tactica | Activo Root | P(Threat)"""
    
    table = Table()
    table.add_column("TTP ID", style="cyan", width=12, justify="center")
    table.add_column("Nombre", style="green", justify="center")
    table.add_column("Tactica", style="yellow", width=20, justify="center")
    table.add_column("Activo Root", style="blue", no_wrap=True, justify="center")
    table.add_column("P(Threat)", style="red", width=12, justify="center")

    ttps = info["summary"]["ttps"]
    for ttp in ttps:
        # Obtener el activo root (es el que está en "asset")
        root_asset = ttp.get("asset", "N/A")
        confidence = ttp.get("confidence", 0)
        
        # Formatear la confianza como porcentaje
        confidence_str = f"{confidence*100:.1f}%"
        
        table.add_row(
            ttp["id"],
            ttp["name"][:28],
            ttp["tactic"][:30],
            root_asset + ' (' + ttp.get("asset_name", "Unknown") + ')',
            confidence_str
        )
    
    panel = Panel(
        Align.center(table),
        title="[TTP Analysis]",
        border_style="magenta",
        padding=(1, 1),
        expand=True  # Ocupa todo el ancho disponible
    )

    return panel




def build_dashboard(info):

    n_ttps = len(info["summary"]["ttps"])
    size_ttps_table_risk = 8 + n_ttps  # Ajustar el tamaño de la tabla según el número de TTPs

    layout = Layout()

    # Estructura principal: dividir en 3 partes verticales
    layout.split_column(
        Layout(render_header(), size=4),           # Header arriba
        Layout(name="content", size=10),           # Content en el medio
        Layout(render_ttps_table(info), size=size_ttps_table_risk)            # TTPs abajo (se ajusta)
    )

    # En el content: dividir en dos columnas
    layout["content"].split_row(
        Layout(render_summary_panel(info)),
        Layout(render_risk_panel(info))
    )

    return layout


def main():
    info = extract_report_data(load_report_data())
    dashboard = build_dashboard(info)
    console.print(dashboard)


    report_data = load_report_data()
    #print(report_data["nodes_analysis"])
    #print(len(report_data["nodes_analysis"][0]))

#==============================================[ENTRY POINT]==============================================#
if __name__ == "__main__":
    main()