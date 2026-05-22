"""
Se construye el reporte JSON de una ejecución de análisis CARE.
Se agregan metadatos, riesgos por activo, riesgo global y escenarios de contramedidas.
"""

#==============================[IMPORTS]===========================================#
from datetime import datetime
import json
from itertools import product

from pathlib import Path

from ..risk.id_test import read_constants

import networkx as nx




#==============================[GLOBAL_CONFIG]===========================================#
global_system_risk = 0.0

DB_PATH = Path(__file__).parent.parent / "database" / "tfg_catalog.db"
EXCEL_PATH = Path(__file__).parent.parent.parent / "data" / "asset_catalog_validado_v1.0.0_ajustado.xlsx"


#===============================[JSON FUNCTIONS]===========================================#

def initialize_simulation_data(threat_vector, scenario_name=None):
    """
    Inicializa la estructura base del reporte de simulación.
    Se añaden metadatos generales y los vectores de amenaza recibidos.

    Args:
        threat_vector: Diccionario con las amenazas o TTPs simuladas.
        scenario_name: Nombre del escenario analizado.

    Returns:
        Diccionario inicial del reporte.
    """
    
    report_data = {
        "metadata": {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "version": "1.0.0",
            "scenario_name": scenario_name,
            "db_path": str(DB_PATH),
            "excel_source": str(EXCEL_PATH)
        }
    }
    
    # Se almacenan todos los TTPs simulados y se prepara la sección de análisis por nodo
    report_data['threat_vectors'] = threat_vector
    report_data['nodes_analysis'] = []
    
    return report_data


def add_graph_metadata(report_data, G_global):
    """
    Añade metadatos del grafo global a la estructura del reporte.

    Args:
        report_data: Diccionario del reporte en construcción.
        G_global: Grafo global de NetworkX usado en el análisis.

    Returns:
        Diccionario del reporte con metadatos del grafo.
    """

    report_data["graph_metadata"] = {
        "total_nodes": len(G_global.nodes()),
        "total_edges": len(G_global.edges()),
        "graph_density": nx.density(G_global),
    }

    return report_data


def include_affected_nodes_and_edges(report_data, affected_nodes_by_level, affected_edges_by_level):
    """
    Incluye nodos y aristas afectados por cada TTP en el reporte.
    Se conserva la organización por niveles de propagación.

    Args:
        report_data: Diccionario del reporte en construcción.
        affected_nodes_by_level: Nodos afectados agrupados por TTP y nivel.
        affected_edges_by_level: Aristas afectadas agrupadas por TTP y nivel.

    Returns:
        Diccionario del reporte con propagación de impacto incorporada.
    """
    
    # Se incorpora la propagación calculada para cada TTP
    for ttp_id in affected_nodes_by_level.keys():
        report_data['threat_vectors'][ttp_id]['affected_nodes'] = affected_nodes_by_level[ttp_id]
        report_data['threat_vectors'][ttp_id]['affected_edges'] = affected_edges_by_level[ttp_id]
    return report_data


def include_node_analysis(report_data, res_threat_prob):
    """
    Incluye un bloque de análisis por nodo en el reporte.

    Args:
        report_data: Diccionario del reporte en construcción.
        res_threat_prob: Resultado de análisis de amenazas por nodo.

    Returns:
        Diccionario del reporte con el nuevo bloque añadido.
    """
    
    report_data['nodes_analysis'].append(res_threat_prob)
    
    return report_data


def calculate_global_risk_by_asset(node, eu_cm_c, eu_cm_i, eu_cm_a, G_global):
    """
    Calcula el riesgo global ponderado para un activo.
    Se combinan los riesgos residuales C, I y A con los pesos CIA del nodo.

    Args:
        node: Identificador del activo evaluado.
        eu_cm_c: Resultados de riesgo residual para confidencialidad.
        eu_cm_i: Resultados de riesgo residual para integridad.
        eu_cm_a: Resultados de riesgo residual para disponibilidad.
        G_global: Grafo global que contiene los atributos del activo.

    Returns:
        Riesgo global ponderado del activo.
    """
    node_data = G_global.nodes[node]
    global_node_risk = node_data['cia_c'] * eu_cm_c[0]['residual_risk'] + node_data['cia_i'] * eu_cm_i[0]['residual_risk'] + node_data['cia_a'] * eu_cm_a[0]['residual_risk']
    
    return global_node_risk

def calculate_incident_risk(report_data):
    """
    Calcula el riesgo de incidente para cada amenaza asociada a cada activo.
    Se usa la opción sin contramedida como riesgo residual base.

    Args:
        report_data: Diccionario del reporte con análisis por nodo.

    Returns:
        Diccionario del reporte con riesgos de incidente incorporados.
    """

    for block in report_data.get("nodes_analysis", []):
        for node, node_info in block.items():

            threats_by_ttp = node_info.get("threats_by_ttp", {})
            influence_by_ttp = node_info.get("influence_diagram_results_by_ttp", {})

            for ttp, threat_info in threats_by_ttp.items():

                influence_info = influence_by_ttp.get(ttp, {})
                expected_utility_by_cm = influence_info.get("expected_utility_by_cm", {})

                # Se toma la opción "none" como línea base sin contramedidas
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

    Args:
        report_data: Diccionario del reporte con riesgos de incidente.

    Returns:
        Diccionario del reporte con riesgo agregado por activo.
    """

    asset_risk_summary = {}

    # Se acumulan riesgos por activo a partir de sus incidentes
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

    # Se escriben medias de riesgo en cada activo analizado
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
    """
    Calcula el riesgo global ponderado del sistema.
    Se agregan los riesgos de los activos usando su criticidad.

    Args:
        report_data: Diccionario del reporte con riesgos agregados por activo.

    Returns:
        Diccionario del reporte con el bloque global_system_risk.
    """

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
    """
    Exporta la estructura de datos del reporte a un archivo JSON.

    Args:
        report_data: Diccionario del reporte que se desea exportar.
        output_filename: Nombre del archivo JSON de salida.

    Returns:
        Ruta del archivo JSON generado.
    """
    reporting_path = Path(__file__).parent / output_filename
    reporting_path.parent.mkdir(parents=True, exist_ok=True)
    
    with open(reporting_path, "w", encoding="utf-8") as f:
        json.dump(report_data, f, indent=2, ensure_ascii=False)
    
    print(f"Reporte exportado a: {reporting_path}")
    return reporting_path


#===============================[SCENARIO EVALUATION SECTION]===========================================#

def extract_candidate_countermeasures(report_data):
    """
    Extrae contramedidas candidatas desde los diagramas de influencia.
    Se eliminan duplicados cuando una misma contramedida aparece en varias dimensiones CIA.

    Args:
        report_data: Diccionario del reporte con resultados de diagramas de influencia.

    Returns:
        Diccionario de contramedidas candidatas por activo y TTP.
    """
    
    candidate_cms = {}
    
    for block in report_data.get("nodes_analysis", []):
        for asset, asset_info in block.items():
            
            influence_by_ttp = asset_info.get("influence_diagram_results_by_ttp", {})
            
            if asset not in candidate_cms:
                candidate_cms[asset] = {}
            
            for ttp, influence_info in influence_by_ttp.items():
                optimal_cm = influence_info.get("optimal_cm", {})
                
                # Se extraen las contramedidas óptimas de cada dimensión CIA
                cms = [
                    optimal_cm.get("C"),
                    optimal_cm.get("I"),
                    optimal_cm.get("A")
                ]
                
                # Se conservan contramedidas únicas manteniendo el orden
                unique_cms = []
                for cm in cms:
                    if cm and cm not in unique_cms:
                        unique_cms.append(cm)
                
                candidate_cms[asset][ttp] = unique_cms
    
    return candidate_cms



def calculate_risk_for_countermeasure(node_info, ttp, countermeasure):
    """
    Calcula el riesgo de incidente para una contramedida específica.
    Se ponderan los riesgos residuales C, I y A con los pesos CIA del activo.

    Args:
        node_info: Diccionario con la información del activo evaluado.
        ttp: Identificador de la amenaza analizada.
        countermeasure: Contramedida aplicada en el escenario.

    Returns:
        Diccionario con riesgos por dimensión CIA y riesgo total del incidente.
    """
    
    influence_by_ttp = node_info.get("influence_diagram_results_by_ttp", {})
    influence_info = influence_by_ttp.get(ttp, {})
    expected_utility_by_cm = influence_info.get("expected_utility_by_cm", {})
    
    # Se obtienen riesgos residuales y pesos CIA para calcular el riesgo total
    residual_risk_c = expected_utility_by_cm.get("C", {}).get(countermeasure, 0.0)
    residual_risk_i = expected_utility_by_cm.get("I", {}).get(countermeasure, 0.0)
    residual_risk_a = expected_utility_by_cm.get("A", {}).get(countermeasure, 0.0)
    
    cia_c = node_info["node_data"]["cia_c"]
    cia_i = node_info["node_data"]["cia_i"]
    cia_a = node_info["node_data"]["cia_a"]
    
    total_risk = (cia_c * residual_risk_c) + (cia_i * residual_risk_i) + (cia_a * residual_risk_a)
    
    return {
        "incident_risk_C": residual_risk_c,
        "incident_risk_I": residual_risk_i,
        "incident_risk_A": residual_risk_a,
        "total_incident_risk": total_risk
    }


def generate_incident_scenarios(report_data):
    """
    Genera escenarios de evaluación de riesgo para cada incidente.
    Se crea un escenario base y un escenario por cada contramedida candidata.

    Args:
        report_data: Diccionario del reporte con amenazas y diagramas de influencia.

    Returns:
        Diccionario del reporte con escenarios de incidente incorporados.
    """
    
    # Se extraen contramedidas candidatas y se construyen escenarios por incidente
    candidate_cms = extract_candidate_countermeasures(report_data)
    
    for block in report_data.get("nodes_analysis", []):
        for asset, asset_info in block.items():
            
            if "incidents" not in asset_info:
                asset_info["incidents"] = {}
            
            threats_by_ttp = asset_info.get("threats_by_ttp", {})
            incident_counter = 1
            
            for ttp, threat_info in threats_by_ttp.items():
                
                incident_key = f"1-{incident_counter}"
                
                cms_for_ttp = candidate_cms.get(asset, {}).get(ttp, [])
                
                asset_info["incidents"][incident_key] = {
                    "ttp": ttp,
                    "candidate_countermeasures": cms_for_ttp,
                    "scenarios": {}
                }
                
                # Se registra el escenario base sin contramedidas y sus alternativas
                baseline_risk = calculate_risk_for_countermeasure(asset_info, ttp, "none")
                asset_info["incidents"][incident_key]["scenarios"]["baseline"] = {
                    "countermeasure": "none",
                    **baseline_risk
                }
                
                for cm in cms_for_ttp:
                    cm_risk = calculate_risk_for_countermeasure(asset_info, ttp, cm)
                    asset_info["incidents"][incident_key]["scenarios"][f"cm_{cm}"] = {
                        "countermeasure": cm,
                        **cm_risk
                    }
                
                incident_counter += 1
    
    return report_data


def generate_asset_scenario_combinations(report_data):
    """
    Genera escenarios de evaluación a nivel de activo.
    Se aplica una única contramedida globalmente a todos los incidentes del activo.

    Args:
        report_data: Diccionario del reporte con escenarios de incidente.

    Returns:
        Diccionario del reporte con escenarios agregados por activo.
    """
    
    for block in report_data.get("nodes_analysis", []):
        for asset, asset_info in block.items():
            
            incidents = asset_info.get("incidents", {})
            
            # Se omiten activos sin incidentes evaluables
            if not incidents:
                continue
            
            # Se recopilan las contramedidas únicas del activo
            unique_cms = set()
            unique_cms.add("none")
            
            for incident_key, incident_data in incidents.items():
                for scenario_name, scenario_data in incident_data["scenarios"].items():
                    cm = scenario_data["countermeasure"]
                    if cm and cm != "none":
                        unique_cms.add(cm)
            
            incident_keys = sorted(incidents.keys())
            
            asset_info["asset_scenarios"] = {}
            
            # Se evalúa cada contramedida como decisión global del activo
            for cm in unique_cms:
                
                if cm == "none":
                    scenario_key = "baseline"
                else:
                    scenario_key = f"cm_{cm}"
                
                total_risk_c = 0.0
                total_risk_i = 0.0
                total_risk_a = 0.0
                total_risk = 0.0
                incidents_with_cm = {}
                
                # Si la contramedida no cubre un incidente, se conserva su baseline.
                for incident_key in incident_keys:
                    incident_data = incidents[incident_key]
                    
                    found_scenario = None
                    for scenario_name, scenario_data in incident_data["scenarios"].items():
                        if scenario_data["countermeasure"] == cm:
                            found_scenario = scenario_name
                            break
                    
                    selected_scenario = found_scenario or "baseline"
                    scenario_data = incident_data["scenarios"][selected_scenario]
                    incidents_with_cm[incident_key] = selected_scenario
                    
                    total_risk_c += scenario_data["incident_risk_C"]
                    total_risk_i += scenario_data["incident_risk_I"]
                    total_risk_a += scenario_data["incident_risk_A"]
                    total_risk += scenario_data["total_incident_risk"]
                
                # Se calculan promedios de riesgo del activo bajo el escenario global
                num_incidents = len(incident_keys)
                avg_risk_c = total_risk_c / num_incidents
                avg_risk_i = total_risk_i / num_incidents
                avg_risk_a = total_risk_a / num_incidents
                avg_total_risk = total_risk / num_incidents
                
                asset_info["asset_scenarios"][scenario_key] = {
                    "countermeasure_applied": cm,
                    "incidents_scenarios": incidents_with_cm,
                    "asset_risk_C": avg_risk_c,
                    "asset_risk_I": avg_risk_i,
                    "asset_risk_A": avg_risk_a,
                    "total_asset_risk": avg_total_risk
                }
    
    return report_data
