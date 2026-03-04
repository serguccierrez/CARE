#==============================[IMPORTS]===========================================#
from datetime import datetime
from ..cyberrecom.main import DB_PATH, EXCEL_PATH
from ..risk.id_test import read_constants


CPDS = read_constants()

global_system_risk = 0.0




#===============================[JSON FUNCTIONS]===========================================#

def initialize_simulation_data(threat_vector: dict) -> dict:
    """Inicializa la estructura de datos para almacenar resultados de simulación"""
    
    return {
        "metadata": {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "version": "1.0.0",
            "threat_ttp_id": threat_vector['ttp_id'],
            "threat_confidence": float(threat_vector['confidence']),
            "initial_asset": threat_vector['asset'],
            "tactic": threat_vector['tactic'],
            "db_path": str(DB_PATH),
            "excel_source": str(EXCEL_PATH)
        },
        "threat_vector": threat_vector,
        "affected_nodes": {},
        "affected_edges": {},
        "levels_analysis": {},
        "Summary": {}
    }
    
def include_affected_nodes_and_edges(report_data,affected_nodes_by_level, affected_edges_by_level):
    """Incluye los nodos y aristas afectados en la estructura de datos del reporte"""
    
    report_data['affected_nodes'] = affected_nodes_by_level
    report_data['affected_edges'] = affected_edges_by_level
    
    return report_data

def include_levels_analysis(report_data, node, p_threat, c_res_levels, i_res_levels, a_res_levels, optimal_cm_C, optimal_cm_I, optimal_cm_A, EU_by_cm_C, EU_by_cm_I, EU_by_cm_A, p_cm_C, p_cm_I, p_cm_A, G_global, level):
    """Incluye el análisis por niveles en la estructura de datos del reporte"""
    
    # Enriquecer EU y p_cm con nombres de contramedidas
    eu_cm_c = []
    eu_cm_i = []
    eu_cm_a = []
    p_cm_c_mapped = []
    p_cm_i_mapped = []
    p_cm_a_mapped = []
    
    for cm, eu in zip(CPDS["CM"]["states"], EU_by_cm_C):
        eu_cm_c.append({'cm': cm, 'residual_risk': abs(eu)})
    optimal_cm_C = min(eu_cm_c, key=lambda x: x['residual_risk'])['cm'] 
    
    for cm, eu in zip(CPDS["CM"]["states"], EU_by_cm_I):
        eu_cm_i.append({'cm': cm, 'residual_risk': abs(eu)})
    optimal_cm_I = min(eu_cm_i, key=lambda x: x['residual_risk'])['cm'] 
    
    for cm, eu in zip(CPDS["CM"]["states"], EU_by_cm_A):
        eu_cm_a.append({'cm': cm, 'residual_risk': abs(eu)})
    optimal_cm_A = min(eu_cm_a, key=lambda x: x['residual_risk'])['cm'] 
    
    # Convertir p_cm a lista si es numpy array
    p_cm_c_list = p_cm_C.tolist() 
    p_cm_i_list = p_cm_I.tolist() 
    p_cm_a_list = p_cm_A.tolist() 
    
    for cm, p in zip(CPDS["CM"]["states"], p_cm_c_list):
        p_cm_c_mapped.append({'cm': cm, 'p': p})
    
    for cm, p in zip(CPDS["CM"]["states"], p_cm_i_list):
        p_cm_i_mapped.append({'cm': cm, 'p': p})
    
    for cm, p in zip(CPDS["CM"]["states"], p_cm_a_list):
        p_cm_a_mapped.append({'cm': cm, 'p': p})
    
    if level not in report_data['levels_analysis']:
        report_data['levels_analysis'][level] = {"results": []}
    
    report_data['levels_analysis'][level]["results"].append({
        "node": node,
        "P(Threat)": p_threat,
        "Asset_weights": G_global.nodes[node],
        "Contextual_awareness_risk":{
        "Global_Risk": calculate_global_risk_by_asset(node, eu_cm_c, eu_cm_i, eu_cm_a, G_global),
        "Confidentiality_Risk": calculate_confidentiality_risk_by_asset(node, eu_cm_c, G_global),
        "Integrity_Risk": calculate_integrity_risk_by_asset(node, eu_cm_i, G_global),
        "Availability_Risk": calculate_availability_risk_by_asset(node, eu_cm_a, G_global),
        },
        "bayesian_inference": {
            "c_res": c_res_levels,
            "i_res": i_res_levels,
            "a_res": a_res_levels,
        },
        "influence_diagram_inference": {
            "Confidentiality": {
                "EU_by_cm": eu_cm_c,
                "p_cm": p_cm_c_mapped,
                "optimal_cm": optimal_cm_C
            },
            "Integrity": {
                "EU_by_cm": eu_cm_i,
                "p_cm": p_cm_i_mapped,
                "optimal_cm": optimal_cm_I
            },
            "Availability": {
                "EU_by_cm": eu_cm_a,
                "p_cm": p_cm_a_mapped,
                "optimal_cm": optimal_cm_A
            }
        },   
    })

    
    return report_data

def calculate_global_risk_by_asset(node, eu_cm_c, eu_cm_i, eu_cm_a, G_global):
    """Calcula el riesgo global por activo basado en los resultados de la simulación"""
    node_data = G_global.nodes[node]
    global_node_risk = node_data['criticality'] * (node_data['cia_c'] * eu_cm_c[0]['residual_risk'] + node_data['cia_i'] * eu_cm_i[0]['residual_risk'] + node_data['cia_a'] * eu_cm_a[0]['residual_risk'])
    
    return global_node_risk

def calculate_confidentiality_risk_by_asset(node, eu_cm_c, G_global):
    """Calcula el riesgo de confidencialidad por activo basado en los resultados de la simulación"""
    node_data = G_global.nodes[node]
    confidentiality_risk = node_data['criticality'] * node_data['cia_c'] * eu_cm_c[0]['residual_risk']
    
    return confidentiality_risk

def calculate_integrity_risk_by_asset(node, eu_cm_i, G_global):
    """Calcula el riesgo de integridad por activo basado en los resultados de la simulación"""
    node_data = G_global.nodes[node]
    integrity_risk = node_data['criticality'] * node_data['cia_i'] * eu_cm_i[0]['residual_risk']
    
    return integrity_risk

def calculate_availability_risk_by_asset(node, eu_cm_a, G_global):
    """Calcula el riesgo de disponibilidad por activo basado en los resultados de la simulación"""
    node_data = G_global.nodes[node]
    availability_risk = node_data['criticality'] * node_data['cia_a'] * eu_cm_a[0]['residual_risk']
    
    return availability_risk

def calculate_system_global_risk(report_data):
    """Calcula el riesgo global del sistema sumando todos los Global_Risk de cada nodo"""
    
    total_system_risk = 0.0
    total_confidentiality_risk = 0.0
    total_integrity_risk = 0.0
    total_availability_risk = 0.0
    
    total_criticality = 0.0
    
    # Iterar por cada nivel
    for level, level_data in report_data['levels_analysis'].items():
        # Iterar por cada nodo en el nivel
        for result in level_data['results']:
            total_system_risk += result['Contextual_awareness_risk']['Global_Risk']
            total_confidentiality_risk += result['Contextual_awareness_risk']['Confidentiality_Risk']
            total_integrity_risk += result['Contextual_awareness_risk']['Integrity_Risk']
            total_availability_risk += result['Contextual_awareness_risk']['Availability_Risk']
            
            total_criticality += result['Asset_weights']['criticality']

            
            
    report_data['Summary'] = {
        "Contextual_awareness_risk": {
            "Total_Global_Risk": total_system_risk,
            "Total_Confidentiality_Risk": total_confidentiality_risk,
            "Total_Integrity_Risk": total_integrity_risk,
            "Total_Availability_Risk": total_availability_risk
        },
        "System_Risk_Score_1_10":total_system_risk / total_criticality
    }
    
    return report_data