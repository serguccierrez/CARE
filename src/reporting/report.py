#==============================[IMPORTS]===========================================#
from datetime import datetime
import json

from pathlib import Path
from ..cyberrecom.main import DB_PATH, EXCEL_PATH
from ..risk.id_test import read_constants

import networkx as nx


CPDS = read_constants()

global_system_risk = 0.0




#===============================[JSON FUNCTIONS]===========================================#

def initialize_simulation_data(threat_vector):
    """Inicializa la estructura de datos para almacenar resultados de simulación"""
    
    report_data = {
        "metadata": {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "version": "1.0.0",
            "db_path": str(DB_PATH),
            "excel_source": str(EXCEL_PATH)
        }
    }
    
    # Podemos recibir más de un TTP en el threat_vector, así que añadimos una sección para almacenar todos los TTPs simulados
    report_data['threat_vectors'] = threat_vector
    report_data['nodes_analysis'] = []
    
    return report_data


def add_graph_metadata(report_data, G_global):
    """Añade metadatos del grafo a la estructura de datos del reporte"""

    report_data["graph_metadata"] = {
        "total_nodes": len(G_global.nodes()),
        "total_edges": len(G_global.edges()),
        "graph_density": nx.density(G_global),
    }

    return report_data


def include_affected_nodes_and_edges(report_data, affected_nodes_by_level, affected_edges_by_level):
    """Incluye los nodos y aristas afectados en la estructura de datos del reporte"""
    
    # Recibimos dos diccionarios, uno con nodos afectados por cada TTP y otro con aristas afectadas por cada TTP, ambos organizados por niveles de propagación (nivel 1, nivel 2, etc.)
    for ttp_id in affected_nodes_by_level.keys():
        report_data['threat_vectors'][ttp_id]['affected_nodes'] = affected_nodes_by_level[ttp_id]
        report_data['threat_vectors'][ttp_id]['affected_edges'] = affected_edges_by_level[ttp_id]
    return report_data


def include_node_analysis(report_data, res_threat_prob):
    """Incluye el análisis por nodo en la estructura de datos del reporte"""
    
    report_data['nodes_analysis'].append(res_threat_prob)
    
    return report_data


def calculate_global_risk_by_asset(node, eu_cm_c, eu_cm_i, eu_cm_a, G_global):
    """Calcula el riesgo global por activo basado en los resultados de la simulación"""
    node_data = G_global.nodes[node]
    global_node_risk = node_data['cia_c'] * eu_cm_c[0]['residual_risk'] + node_data['cia_i'] * eu_cm_i[0]['residual_risk'] + node_data['cia_a'] * eu_cm_a[0]['residual_risk']
    
    return global_node_risk

def calculate_incident_risk(report_data):
    """Añade incident_risk_C, incident_risk_I, incident_risk_A y total_incident_risk"""

    for block in report_data.get("nodes_analysis", []):
        for node, node_info in block.items():

            threats_by_ttp = node_info.get("threats_by_ttp", {})
            influence_by_ttp = node_info.get("influence_diagram_results_by_ttp", {})

            for ttp, threat_info in threats_by_ttp.items():

                influence_info = influence_by_ttp.get(ttp, {})
                expected_utility_by_cm = influence_info.get("expected_utility_by_cm", {})

                # Riesgo residual usando la opción "none"
                residual_risk_c = expected_utility_by_cm.get("C", {}).get("none", 0.0)
                residual_risk_i = expected_utility_by_cm.get("I", {}).get("none", 0.0)
                residual_risk_a = expected_utility_by_cm.get("A", {}).get("none", 0.0)

                threat_info["incident_risk_C"] = residual_risk_c
                threat_info["incident_risk_I"] = residual_risk_i
                threat_info["incident_risk_A"] = residual_risk_a

                threat_info["total_incident_risk"] = (node_info["node_data"]["cia_c"] * residual_risk_c) + (node_info["node_data"]["cia_i"] * residual_risk_i) + (node_info["node_data"]["cia_a"] * residual_risk_a)

    return report_data
    
def total_risk_by_asset(report_data):
    """
    Calcula el riesgo total por activo como la media aritmética de los incidentes
    asociados a ese activo, tanto global como por cada dimensión CIA.
    """

    asset_risk_summary = {}

    # Primera pasada: acumular riesgos por activo
    for block in report_data.get("nodes_analysis", []):
        for node, node_info in block.items():

            threats_by_ttp = node_info.get("threats_by_ttp", {})

            for ttp, threat_info in threats_by_ttp.items():
                
                total_incident_risk = threat_info.get("total_incident_risk", 0.0)
                incident_risk_C = threat_info.get("incident_risk_C", 0.0)
                incident_risk_I = threat_info.get("incident_risk_I", 0.0)
                incident_risk_A = threat_info.get("incident_risk_A", 0.0)   
                

                if node not in asset_risk_summary:
                    asset_risk_summary[node] = {
                        "total_incident_risk": 0.0,
                        "total_incident_risk_C": 0.0,
                        "total_incident_risk_I": 0.0,
                        "total_incident_risk_A": 0.0,
                        "incident_count": 0
                    }

                asset_risk_summary[node]["total_incident_risk"] += total_incident_risk
                asset_risk_summary[node]["total_incident_risk_C"] += incident_risk_C
                asset_risk_summary[node]["total_incident_risk_I"] += incident_risk_I
                asset_risk_summary[node]["total_incident_risk_A"] += incident_risk_A
                asset_risk_summary[node]["incident_count"] += 1

    # Segunda pasada: escribir resultados en cada activo
    for block in report_data.get("nodes_analysis", []):
        for node, node_info in block.items():

            risk_info = asset_risk_summary.get(node, None)

            if risk_info and risk_info["incident_count"] > 0:
                n = risk_info["incident_count"]

                node_info["asset_incident_count"] = n
                node_info["asset_average_risk"] = risk_info["total_incident_risk"] / n
                node_info["asset_confidentiality_risk"] = risk_info["total_incident_risk_C"] / n
                node_info["asset_integrity_risk"] = risk_info["total_incident_risk_I"] / n
                node_info["asset_availability_risk"] = risk_info["total_incident_risk_A"] / n
            else:
                node_info["asset_incident_count"] = 0
                node_info["asset_average_risk"] = 0.0
                node_info["asset_confidentiality_risk"] = 0.0
                node_info["asset_integrity_risk"] = 0.0
                node_info["asset_availability_risk"] = 0.0

    return report_data
    
    

def calculate_global_system_risk(report_data):
    """ Calcula el reisgo global del sistema"""

    risk_score_c = 0.0
    risk_score_i = 0.0
    risk_score_a = 0.0
    risk_score = 0.0
    system_criticality = 0.0

    for block in report_data.get("nodes_analysis", []):
        for node, node_info in block.items():

            c_risk = node_info.get("asset_confidentiality_risk", 0.0)
            i_risk = node_info.get("asset_integrity_risk", 0.0)
            a_risk = node_info.get("asset_availability_risk", 0.0)
            
            node_criticality = node_info["node_data"].get("criticality", 0.0)
            
            system_criticality += node_info["node_data"].get("criticality", 0.0)
            
            risk_score_c += c_risk * node_criticality
            risk_score_i += i_risk * node_criticality
            risk_score_a += a_risk * node_criticality
            
            risk_score += node_info.get("asset_average_risk", 0.0) * node_criticality
           
                
    risk_score_c = risk_score_c / system_criticality 
    risk_score_i = risk_score_i / system_criticality
    risk_score_a = risk_score_a / system_criticality
    risk_score = risk_score / system_criticality
    
    report_data['global_system_risk'] = {
        "confidentiality_risk": risk_score_c,
        "integrity_risk": risk_score_i,
        "availability_risk": risk_score_a,
        "overall_risk": risk_score
    }
    
    return report_data

def export_report_to_json(report_data, output_filename="report.json"):
    """Exporta la estructura de datos del reporte a un archivo JSON"""
    reporting_path = Path(__file__).parent / output_filename
    reporting_path.parent.mkdir(parents=True, exist_ok=True)
    
    with open(reporting_path, "w", encoding="utf-8") as f:
        json.dump(report_data, f, indent=2, ensure_ascii=False)
    
    print(f"Reporte exportado a: {reporting_path}")
    return reporting_path

