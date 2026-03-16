#==============================================[IMPORTS]==============================================#
import json
from rich.console import Console
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
    
    # Extraer datos de TTPs de forma estructurada
    ttps_list = []
    for ttp_id, ttp_data in threat_vectors.items():
        ttps_list.append({
            "id": ttp_id,
            "name": ttp_data.get("name", "Unknown"),
            "tactic": ttp_data.get("tactic", "N/A"),
            "asset": ttp_data.get("asset", "N/A"),
            "confidence": ttp_data.get("confidence", 0),
            "affected_nodes": ttp_data.get("affected_nodes", {})
        })
    
    # === NODES ANALYSIS ===
    nodes_analysis = report_data.get("nodes_analysis", [])
    n_affected_assets = len(nodes_analysis[0]) if nodes_analysis else 0
    
    overall_risk = report_data.get("global_system_risk", {}).get("overall_risk", "N/A")
    info["summary"] = {
        "vectores_numero": n_threat_vectors,
        "activos_afectados": n_affected_assets,
        "riesgo_general": overall_risk,
        "ttps": ttps_list
    }
    return info
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
    summary_text = f"""
[bold]Initial Compromised Asset:[/bold] asset_006
[bold]Threat TTP:[/bold] T1027.008
[bold]Tactic:[/bold] Defense Evasion
[bold]Total Threat Vectors:[/bold] {info["summary"]["vectores_numero"]}
[bold]Affected Assets:[/bold] {info["summary"]["activos_afectados"]}
[bold]Percentage of Network Affected:[/bold] 
"""

    panel = Panel(
        summary_text,
        title="Operational Summary",
        border_style="yellow",
    )

    panel = Panel(
        summary_text,
        title="Operational Summary",
        border_style="yellow",
    )

    return panel


def render_risk_panel(info):

    risk_value = round(info["summary"]["riesgo_general"], 2)

    bar = ProgressBar(
        total=10,
        completed=risk_value,
    )

    risk_text = Text()
    risk_text.append("Overall System Risk\n", style="bold")
    risk_text.append(f"{risk_value}/10\n\n")

    panel = Panel(
        Columns([risk_text, bar]),
        title="Global Risk Level",
        border_style="red",
    )

    return panel


def render_ttps_table(info):
    """Renderiza tabla con TTP | Nombre | Tactica | Activo Root | P(Threat)"""
    
    table = Table(title="Threat Threat Patterns (TTPs) Analysis", show_header=True, header_style="bold magenta")
    table.add_column("TTP ID", style="cyan", width=12)
    table.add_column("Nombre", style="green", width=30)
    table.add_column("Tactica", style="yellow", width=20)
    table.add_column("Activo Root", style="blue", width=15)
    table.add_column("P(Threat)", style="red", width=12)
    
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
            ttp["tactic"][:18],
            root_asset,
            confidence_str
        )
    
    panel = Panel(
        table,
        title="[TTP Analysis]",
        border_style="magenta",
        padding=(1, 1),
    )
    
    return panel


def build_dashboard(info):

    layout = Layout()

    # Estructura principal: dividir en 3 partes verticales
    layout.split_column(
        Layout(render_header(), size=6),           # Header arriba
        Layout(name="content", size=15),           # Content en el medio
        Layout(render_ttps_table(info))            # TTPs abajo (se ajusta)
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