#=============================[IMPORTS]===========================================#
from datetime import datetime
import json
import random
import networkx as nx
from pathlib import Path

import src.cyberrecom.mitre as mitre
import src.graph.grafo as grafo


import src.reporting.report as report

import src.cyberrecom.mitre as mitre

import src.risk.red_bayes as red_bayes
import src.risk.id_test as id_test

#=============================[CONSTANTS]===========================================#
#DB_PATH = Path(__file__).parent.parent / "database" / "tfg_catalog_v1.0.0.db"
DB_PATH = Path(__file__).parent.parent / "database" / "tfg_catalog.db"
EXCEL_PATH = Path(__file__).parent.parent.parent / "data" / "asset_catalog_validado_v1.0.0_ajustado.xlsx"
CPDS = id_test.read_constants()

#==============================[MAIN FUNCTION]===========================================#


def resolve_scenario(scenario_name: str) -> None:
    G_global = grafo.build_MDO_graph(str(DB_PATH), scenario_name )
    
    return G_global


def _ensure_list(value):
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]
    
def resolve_threat_vector(G_global, context) -> None:
    
    mode = context["mode"]
    selected_assets = _ensure_list(context.get("selected_asset"))
    selected_ttps = _ensure_list(context.get("selected_ttps"))
    selected_confidences = _ensure_list(context.get("selected_confidences"))
    
    if mode == "random":
    
        #Simulamos una amenaza aleatoria que puede contener 1 o más vectores de ataque (TTPs) con un cierto nivel de confidence. Solo selecciona TTPs que existen realmente en MITRE ATT&CK.
        threat_vectors = mitre.ttp_simulation()  # Es un diccionario con keys 'ttp_id' y 'confidence' (puede haber más de un TTP)
        
        for ttp_id, threat_vector in threat_vectors.items():
            random_asset = random.choice(list(G_global.nodes)) #Seleccionamos un activo aleatorio del grafo MDO para simular que es el activo afectado por esta amenazañ
            print(threat_vector)
            confidence = threat_vector['confidence']
            ttp_tactic = threat_vector['tactic']
            threat_vector['asset'] = random_asset #Añadimos el activo afectado a cada TTP del vector de amenaza
            
            print(f"\nSimulación de amenaza: TTP={ttp_id}, Confidence={confidence:.5f}, Asset={random_asset}, Tactic={ttp_tactic}")
    
    else:
        threat_vectors = {}
        max_len = max(len(selected_assets), len(selected_ttps), len(selected_confidences), 1)

        for idx in range(max_len):
            asset = selected_assets[idx] if idx < len(selected_assets) else None
            ttp = selected_ttps[idx] if idx < len(selected_ttps) else None
            confidence = selected_confidences[idx] if idx < len(selected_confidences) else None

            if asset is None:
                asset = random.choice(list(G_global.nodes))

            if ttp is None:
                ttp = mitre.single_ttp_simulation()

            if confidence is None:
                confidence = ttp["confidence"] if isinstance(ttp, dict) and "confidence" in ttp else random.uniform(0.3, 1.0)

            if isinstance(ttp, dict):
                ttp_id = ttp["ttp_id"]
                ttp_details = ttp.get("tactic") or mitre.get_ttp_details_from_ttp_id(ttp_id)
            else:
                ttp_id = ttp
                ttp_details = mitre.get_ttp_details_from_ttp_id(ttp_id)

            threat_vectors[ttp_id] = {
                "confidence": confidence,
                "tactic": ttp_details,
                "asset": asset
            }
            
    #{Inicializo JSON de reporte}
    report_data = report.initialize_simulation_data(threat_vectors)
    report_data = report.add_graph_metadata(report_data, G_global)
    
    return threat_vectors, report_data
    
    
def resolve_graph_impact(G_global, threat_vectors, report_data):
    
    # Definimos diccionarios para almacenar nodos y aristas afectados por cada TTP de los vectores de amenaza
    affected_nodes = {}
    affected_edges = {}

    for ttp_id, threat_vector in threat_vectors.items():
        nodes, edges = grafo.get_infected_nodes(G_global, threat_vector['asset'])
        affected_nodes[ttp_id] = nodes
        affected_edges[ttp_id] = edges
   
    report_data = report.include_affected_nodes_and_edges(report_data, affected_nodes, affected_edges)
    
    res_threat_prob = red_bayes.get_res_threat_prob(affected_edges, affected_nodes, threat_vectors, G_global)
    
    return res_threat_prob, report_data


def resolve_build_res_values(cm_states, countermeasures_data, dimension):
    columns = []

    for cm_id in cm_states:
        columns.append(
            countermeasures_data["countermeasures"][cm_id]["cpd"][dimension]["risk_low"]
        )

    for cm_id in cm_states:
        columns.append(
            countermeasures_data["countermeasures"][cm_id]["cpd"][dimension]["risk_high"]
        )

    values = [
        [col[0] for col in columns],
        [col[1] for col in columns],
        [col[2] for col in columns],
    ]

    return values

def resolve_bn_json_construction(res_threat_prob, threat_vectors, report_data):
    '''
    Esta función se encarga de sacar las mitigations recomendadas por cada TTP y construir el JSON de la red de Bayes para cada TTP, que luego se guardará en el reporte. Esto es necesario para poder hacer la inferencia posteriormente.
    '''
    # Cargamos el json bn_cpds.json
    with open(Path(__file__).parent.parent.parent / "configs" / "bn_cpds.json", "r") as f:
        bn_cpds = json.load(f)

     # Cargamos el json countermeasures.json
    with open(Path(__file__).parent.parent.parent / "configs" / "countermeasures.json", "r") as f:
        countermeasures = json.load(f)

    #{CM STATES}#

    raw_mitigations = []
    cm_states = []

    #Añadimos los 3 primeros countermeasures como mitigaciones base, que son aplicables a cualquier TTP. Luego añadiremos las mitigaciones específicas de cada TTP.
    cm_states.append(countermeasures[0:3]["name"]) 

    # Construimos el JSON de la red de Bayes para cada TTP
    for ttp_id, threat_vector in threat_vectors.items():
        raw_mitigations.append(mitre.get_mitigations_for_ttp(ttp_id))


    for cm in raw_mitigations:
        cm_states.append({"id": cm["id"], "name": f"{cm['id']}-{cm['name']}"})

    bn_cpds["CM"]["states"] = cm_states

    #{PROBABILITIES}#
   c_res_values = build_res_values(cm_states, countermeasures_data, "C_res")
i_res_values = build_res_values(cm_states, countermeasures_data, "I_res")
a_res_values = build_res_values(cm_states, countermeasures_data, "A_res")

       








    pass

def resolve_bn_and_id_inference(res_threat_prob, threat_vectors, report_data):
    
    for ttp_id, threat_vector in threat_vectors.items():
        for asset, info_asset in res_threat_prob.items():
            if ttp_id not in info_asset.get('threats_by_ttp', {}):
                continue

            print(f"Calculando red de Bayes para TTP {ttp_id} - Asset {asset}...") 


            red_bayes_model = red_bayes.bayesian_network_construction(
                threat_vector['tactic'],
                info_asset['threats_by_ttp'][ttp_id]['P(Threat)']
            )

            # Hacemos las queries
            threat_prob = red_bayes_model.query(variables=["Threat"])
            c_res = red_bayes_model.query(variables=["C_res"], evidence={"CM": "none"})
            c_res_levels = red_bayes.get_cia_res_levels(c_res)

            i_res = red_bayes_model.query(variables=["I_res"], evidence={"CM": "none"})
            i_res_levels = red_bayes.get_cia_res_levels(i_res)

            a_res = red_bayes_model.query(variables=["A_res"], evidence={"CM": "none"})
            a_res_levels = red_bayes.get_cia_res_levels(a_res)

            # Guardar resultados por TTP, para no sobreescribitr si hay varios TTPs afectando al mismo activo
            info_asset.setdefault('bayesian_network_inference_by_ttp', {})
            info_asset['bayesian_network_inference_by_ttp'][ttp_id] = {
                'queries': {
                    'c_res_levels': c_res_levels,
                    'i_res_levels': i_res_levels,
                    'a_res_levels': a_res_levels
                }
            }

            print(f"Inferencia almacenada para {asset} - {ttp_id}")
            print(f"P(C_res | CM=none): {c_res_levels}")
            print(f"P(I_res | CM=none): {i_res_levels}")
            print(f"P(A_res | CM=none): {a_res_levels}")


            #========================================== PASO 10: Análisis con diagrama de influencia =========================================#
            influence_diagram_C, ie_C = id_test.create_and_solve_dimension("C", "C_res",  threat_vector['tactic'], info_asset['threats_by_ttp'][ttp_id]['P(Threat)'])
            influence_diagram_I, ie_I = id_test.create_and_solve_dimension("I", "I_res",  threat_vector['tactic'], info_asset['threats_by_ttp'][ttp_id]['P(Threat)'])
            influence_diagram_A, ie_A = id_test.create_and_solve_dimension("A", "A_res",  threat_vector['tactic'], info_asset['threats_by_ttp'][ttp_id]['P(Threat)'])

            # Para cada dimensión
            optimal_cm_C = ie_C.optimalDecision("CM")
            optimal_cm_I = ie_I.optimalDecision("CM")
            optimal_cm_A = ie_A.optimalDecision("CM")

            

            # Calcular EU por CM para cada dimensión
            EU_by_cm_C, p_cm_C, h_C = id_test.expected_utility_per_cm(influence_diagram_C)
            EU_by_cm_I, p_cm_I, h_I = id_test.expected_utility_per_cm(influence_diagram_I)
            EU_by_cm_A, p_cm_A, h_A = id_test.expected_utility_per_cm(influence_diagram_A)


            # Lo transformamos en algo que podamos meter en el reporte en formato JSON
            best_cm_C = CPDS["CM"]["states"][EU_by_cm_C.index(max(EU_by_cm_C))]
            best_cm_I = CPDS["CM"]["states"][EU_by_cm_I.index(max(EU_by_cm_I))]
            best_cm_A = CPDS["CM"]["states"][EU_by_cm_A.index(max(EU_by_cm_A))]

            # Devolvemos la utilidad a un valor > 0
            EU_by_cm_C = [abs(x) for x in EU_by_cm_C]
            EU_by_cm_I = [abs(x) for x in EU_by_cm_I]
            EU_by_cm_A = [abs(x) for x in EU_by_cm_A]


            # Guardar resultados ID por TTP
            info_asset.setdefault('influence_diagram_results_by_ttp', {})
            info_asset['influence_diagram_results_by_ttp'][ttp_id] = {
        
                'optimal_cm': {
                    'C': best_cm_C,
                    'I': best_cm_I,
                    'A': best_cm_A
                },
                'expected_utility_by_cm': {
                    'C':dict(zip(CPDS["CM"]["states"], EU_by_cm_C)),
                    'I': dict(zip(CPDS["CM"]["states"], EU_by_cm_I)),
                    'A': dict(zip(CPDS["CM"]["states"], EU_by_cm_A))
                },
                'p_cm': {
                    'C':dict(zip(CPDS["CM"]["states"], p_cm_C.tolist())),
                    'I': dict(zip(CPDS["CM"]["states"], p_cm_I.tolist())),
                    'A': dict(zip(CPDS["CM"]["states"], p_cm_A.tolist()))
                },
                'policy_entropy': {
                    'C': h_C,
                    'I': h_I,
                    'A': h_A
                }
            }

            
            
            # Imprimir resultados
            print("CONFIDENTIALITY:")
            print(f"  Optimal CM: {optimal_cm_C}")
            for cm_state, eu, p in zip(CPDS["CM"]["states"], EU_by_cm_C, p_cm_C):
                print(f"  CM={cm_state}: EU={eu:.4f}, p(CM)={p:.4f}")
            print(f"  Entropy of policy: {h_C:.4f} ")

            print("\nINTEGRITY:")
            print(f"  Optimal CM: {optimal_cm_I}")
            for cm_state, eu, p in zip(CPDS["CM"]["states"], EU_by_cm_I, p_cm_I):
                print(f"  CM={cm_state}: EU={eu:.4f}, p(CM)={p:.4f}")
            print(f"  Entropy of policy: {h_I:.4f} ")

            print("\nAVAILABILITY:")
            print(f"  Optimal CM: {optimal_cm_A}")
            for cm_state, eu, p in zip(CPDS["CM"]["states"], EU_by_cm_A, p_cm_A):
                print(f"  CM={cm_state}: EU={eu:.4f}, p(CM)={p:.4f}")
            print(f"  Entropy of policy: {h_A:.4f} ")

    report_data = report.include_node_analysis(report_data, res_threat_prob)
    
    return report_data


def resolve_risk_assessment(report_data):
    report_data = report.calculate_incident_risk(report_data)
    report_data = report.total_risk_by_asset(report_data)
    report_data = report.calculate_global_system_risk(report_data)
    
    report.export_report_to_json(report_data)
    
    return report_data
    


def main(scenario_name, context ):
    
    #{Constuimos el grafo con el escenario seleccionado}#
    G_global = resolve_scenario(scenario_name)
    
    #{Construimos o simulamos el vector de amenaza}#
    threat_vectors, report_data = resolve_threat_vector(G_global, context)
    
    #{Calculamos el impacto en el grafo}#
    res_threat_prob, report_data = resolve_graph_impact(G_global, threat_vectors, report_data)
    
    #{Realizamos inferencia en la red de Bayes y análisis con diagrama de influencia para cada activo afectado por cada TTP}#
    report_data = resolve_bn_and_id_inference(res_threat_prob, threat_vectors, report_data)
    
    #{Calculamos el riesgo del incidente y exportamos el reporte}#
    report_data = resolve_risk_assessment(report_data)
    
    return report_data

