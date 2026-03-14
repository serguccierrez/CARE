#==============================[IMPORTS]===========================================#
from datetime import datetime
import json
from itertools import product

from pathlib import Path
from ..cyberrecom.main import DB_PATH, EXCEL_PATH
from ..risk.id_test import read_constants


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
       
    
def include_affected_nodes_and_edges(report_data,affected_nodes_by_level, affected_edges_by_level):
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


#===============================[SCENARIO EVALUATION SECTION]===========================================#

def extract_candidate_countermeasures(report_data):
    """Extrae las contramedidas candidatas del diagrama de influencia para cada incidente"""
    
    candidate_cms = {}
    
    for block in report_data.get("nodes_analysis", []):
        for asset, asset_info in block.items():
            
            influence_by_ttp = asset_info.get("influence_diagram_results_by_ttp", {})
            
            if asset not in candidate_cms:
                candidate_cms[asset] = {}
            
            for ttp, influence_info in influence_by_ttp.items():
                optimal_cm = influence_info.get("optimal_cm", {})
                
                # Extraemos las tres contramedidas óptimas: C, I, A
                cms = [
                    optimal_cm.get("C"),
                    optimal_cm.get("I"),
                    optimal_cm.get("A")
                ]
                
                # Deduplicamos: si una CM aparece en varias dimensiones, la guardamos una sola vez
                unique_cms = []
                for cm in cms:
                    if cm and cm not in unique_cms:
                        unique_cms.append(cm)
                
                candidate_cms[asset][ttp] = unique_cms
    
    return candidate_cms



def calculate_risk_for_countermeasure(node_info, ttp, countermeasure):
    """Calcula el riesgo de incidente para una contramedida específica"""
    
    influence_by_ttp = node_info.get("influence_diagram_results_by_ttp", {})
    influence_info = influence_by_ttp.get(ttp, {})
    expected_utility_by_cm = influence_info.get("expected_utility_by_cm", {})
    
    # Obtenemos los riesgos residuales para cada dimensión CIA
    residual_risk_c = expected_utility_by_cm.get("C", {}).get(countermeasure, 0.0)
    residual_risk_i = expected_utility_by_cm.get("I", {}).get(countermeasure, 0.0)
    residual_risk_a = expected_utility_by_cm.get("A", {}).get(countermeasure, 0.0)
    
    # Obtenemos los pesos CIA del activo
    cia_c = node_info["node_data"]["cia_c"]
    cia_i = node_info["node_data"]["cia_i"]
    cia_a = node_info["node_data"]["cia_a"]
    
    # Calculamos el riesgo total ponderado
    total_risk = (cia_c * residual_risk_c) + (cia_i * residual_risk_i) + (cia_a * residual_risk_a)
    
    return {
        "incident_risk_C": residual_risk_c,
        "incident_risk_I": residual_risk_i,
        "incident_risk_A": residual_risk_a,
        "total_incident_risk": total_risk
    }


def generate_incident_scenarios(report_data):
    """Genera escenarios de evaluación de riesgo para cada incidente y contramedida candidata"""
    
    # Primero extraemos las contramedidas candidatas de cada incidente
    candidate_cms = extract_candidate_countermeasures(report_data)
    
    # Ahora creamos los escenarios basados en esas contramedidas
    for block in report_data.get("nodes_analysis", []):
        for asset, asset_info in block.items():
            
            # Inicializamos la sección de incidentes
            if "incidents" not in asset_info:
                asset_info["incidents"] = {}
            
            threats_by_ttp = asset_info.get("threats_by_ttp", {})
            incident_counter = 1
            
            # Procesamos cada TTP del activo
            for ttp, threat_info in threats_by_ttp.items():
                
                # Creamos identificador del incidente (1-1, 1-2, etc.)
                incident_key = f"1-{incident_counter}"
                
                # Obtenemos las contramedidas candidatas para este incidente específico
                cms_for_ttp = candidate_cms.get(asset, {}).get(ttp, [])
                
                # Inicializamos estructura del incidente
                asset_info["incidents"][incident_key] = {
                    "ttp": ttp,
                    "candidate_countermeasures": cms_for_ttp,
                    "scenarios": {}
                }
                
                # Creamos escenario baseline con contramedida "none"
                baseline_risk = calculate_risk_for_countermeasure(asset_info, ttp, "none")
                asset_info["incidents"][incident_key]["scenarios"]["baseline"] = {
                    "countermeasure": "none",
                    **baseline_risk
                }
                
                # Creamos un escenario para cada contramedida candidata
                for cm in cms_for_ttp:
                    cm_risk = calculate_risk_for_countermeasure(asset_info, ttp, cm)
                    asset_info["incidents"][incident_key]["scenarios"][f"cm_{cm}"] = {
                        "countermeasure": cm,
                        **cm_risk
                    }
                
                incident_counter += 1
    
    return report_data


def generate_asset_scenario_combinations(report_data):
    """Genera escenarios de evaluación a nivel de activo: una sola contramedida aplicada globalmente a todos sus incidentes"""
    
    for block in report_data.get("nodes_analysis", []):
        for asset, asset_info in block.items():
            
            incidents = asset_info.get("incidents", {})
            
            # Si el activo no tiene incidentes, saltamos
            if not incidents:
                continue
            
            # Extraemos todas las contramedidas únicas del activo (de todos sus incidentes)
            unique_cms = set()
            unique_cms.add("none")  # Siempre incluimos la opción baseline
            
            for incident_key, incident_data in incidents.items():
                for scenario_name, scenario_data in incident_data["scenarios"].items():
                    cm = scenario_data["countermeasure"]
                    if cm and cm != "none":
                        unique_cms.add(cm)
            
            # Preparamos los identificadores de incidentes ordenados
            incident_keys = sorted(incidents.keys())
            
            # Inicializamos estructura de escenarios del activo
            asset_info["asset_scenarios"] = {}
            
            # Para cada contramedida única, aplicamos globalmente a todos los incidentes
            for cm in unique_cms:
                
                # Creamos identificador del escenario
                if cm == "none":
                    scenario_key = "baseline"
                else:
                    scenario_key = f"cm_{cm}"
                
                # Acumulamos riesgos cuando se aplica esta CM a todos los incidentes
                total_risk_c = 0.0
                total_risk_i = 0.0
                total_risk_a = 0.0
                total_risk = 0.0
                incidents_with_cm = {}
                
                # Para cada incidente, buscamos el escenario con esta CM
                for incident_key in incident_keys:
                    incident_data = incidents[incident_key]
                    
                    # Buscamos el escenario con esta CM en este incidente
                    found_scenario = None
                    for scenario_name, scenario_data in incident_data["scenarios"].items():
                        if scenario_data["countermeasure"] == cm:
                            found_scenario = scenario_name
                            break
                    
                    # Si encontramos el escenario con esta CM, lo usamos
                    if found_scenario:
                        scenario_data = incident_data["scenarios"][found_scenario]
                        incidents_with_cm[incident_key] = found_scenario
                        
                        # Acumulamos riesgos
                        total_risk_c += scenario_data["incident_risk_C"]
                        total_risk_i += scenario_data["incident_risk_I"]
                        total_risk_a += scenario_data["incident_risk_A"]
                        total_risk += scenario_data["total_incident_risk"]
                
                # Calculamos promedios de riesgos
                num_incidents = len(incident_keys)
                avg_risk_c = total_risk_c / num_incidents
                avg_risk_i = total_risk_i / num_incidents
                avg_risk_a = total_risk_a / num_incidents
                avg_total_risk = total_risk / num_incidents
                
                # Almacenamos el escenario del activo
                asset_info["asset_scenarios"][scenario_key] = {
                    "countermeasure_applied": cm,
                    "incidents_scenarios": incidents_with_cm,
                    "asset_risk_C": avg_risk_c,
                    "asset_risk_I": avg_risk_i,
                    "asset_risk_A": avg_risk_a,
                    "total_asset_risk": avg_total_risk
                }
    
    return report_data


#===============================[OPTIMIZATION PROBLEM PREPARATION]===========================================#
