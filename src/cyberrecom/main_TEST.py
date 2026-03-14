#=============================[IMPORTS]===========================================#
from datetime import datetime
import json
import random
import networkx as nx
from pathlib import Path

import src.database.load_data as load_data
import src.cyberrecom.mitre as mitre
import src.graph.grafo as grafo
import src.database.create_db as create_db


import src.reporting.report as report



import src.risk.red_bayes as red_bayes
import src.risk.id_test as id_test

#=============================[CONSTANTS]===========================================#
DB_PATH = Path(__file__).parent.parent / "database" / "tfg_catalog_v1.0.0.db"
EXCEL_PATH = Path(__file__).parent.parent.parent / "data" / "asset_catalog_validado_v1.0.0_ajustado.xlsx"
CPDS = id_test.read_constants()

#==============================[MAIN FUNCTION]===========================================#

def main() -> None:
    """
    Función principal: orquesta todo el flujo.
    1. Crear estructura BD
    2. Cargar datos desde Excel
    3. Construir grafo MDO
    4. Cargar TTPs MITRE ATT&CK
    5. Realizar simulaciones de ataque TTP
    """   
    
    print("\n" + "#"*80)
    print("# Motor de recomendacion de contramedidas en entornos MDO - TFG V1.0.0")
    print("#"*80)
    
    
    # ============ PASO 1: Crear base de datos ============
    print("\n" + "="*80)
    print("PASO 1: CREANDO ESTRUCTURA DE BASE DE DATOS")
    print("="*80)
    if DB_PATH.exists():
        print(f"Base de datos ya existe: {DB_PATH}.")
    else:
        create_db.create_db(DB_PATH, recreate=True)
        print(f"Base de datos creada: {DB_PATH}\n")
    
    
    # ============ PASO 2: Cargar datos desde Excel ============
    print("\n" + "="*80)
    print("PASO 2: CARGAR DATOS DESDE EXCEL")
    print("="*80)
    
    
    # load_data.load_and_insert_data(EXCEL_PATH, DB_PATH)
    
    
    # ============ PASO 3: Construir grafo MDO ============
    print("\n" + "="*80)
    print("PASO 3: CONSTRUIR GRAFO MDO")
    print("="*80)
    
    G_global = grafo.build_MDO_graph(str(DB_PATH))
    
    
    # ============ PASO 4: Simular llegada de una amenaza ============
    print("\n" + "="*80)
    print("PASO 4: SIMULAR LLEGADA DE UNA AMENAZA")
    print("="*80)
    
    #Simulamos una amenaza aleatoria que puede contener 1 o más vectores de ataque (TTPs) con un cierto nivel de confidence. Solo selecciona TTPs que existen realmente en MITRE ATT&CK.
    random_threat_vectors = mitre.ttp_simulation()  # Es un diccionario con keys 'ttp_id' y 'confidence' (puede haber más de un TTP)
    
    for ttp_id, threat_vector in random_threat_vectors.items():
        random_asset = random.choice(list(G_global.nodes)) #Seleccionamos un activo aleatorio del grafo MDO para simular que es el activo afectado por esta amenazañ
        print(threat_vector)
        confidence = threat_vector['confidence']
        ttp_tactic = threat_vector['tactic']
        threat_vector['asset'] = random_asset #Añadimos el activo afectado a cada TTP del vector de amenaza
        
        print(f"\nSimulación de amenaza: TTP={ttp_id}, Confidence={confidence:.5f}, Asset={random_asset}, Tactic={ttp_tactic}")
    
    #{Inicializo JSON de reporte}
    report_data = report.initialize_simulation_data(random_threat_vectors)
    
    # ============ PASO 5: Analizar impacto en el grafo MDO ============
    print("\n" + "="*80)
    print("PASO 5: ANALIZAR IMPACTO EN EL GRAFO MDO")
    print("="*80)
    
    # Definimos diccionarios para almacenar nodos y aristas afectados por cada TTP de los vectores de amenaza
    affected_nodes = {}
    affected_edges = {}

    for ttp_id, threat_vector in random_threat_vectors.items():
        nodes, edges = grafo.get_infected_nodes(G_global, threat_vector['asset'])
        affected_nodes[ttp_id] = nodes
        affected_edges[ttp_id] = edges
        
    print(f"\nNodos afectados por cada TTP: {affected_nodes}")
    print(f"\nAristas afectadas por cada TTP: {affected_edges}")
   
    report_data = report.include_affected_nodes_and_edges(report_data, affected_nodes, affected_edges)
  
    #========================================= PASO 8: Calculo del Threat del siguiente activo dependiente =========================================#
    print("\n" + "="*80)
    print("PASO 8: CALCULO DEL THREAT DEL SIGUIENTE ACTIVO DEPENDIENTE")
    print("="*80)
    
    res_threat_prob = red_bayes.get_res_threat_prob(affected_edges, affected_nodes, random_threat_vectors, G_global)
    print(f"\nProbabilidades de amenaza calculadas para los activos afectados: {res_threat_prob}")
    
    
    #========================================== PASO 9: red de bayes para activos =========================================#
    
    for ttp_id, threat_vector in random_threat_vectors.items():
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
    
    report_data = report.calculate_incident_risk(report_data)
    report_data = report.total_risk_by_asset(report_data)
    report_data = report.calculate_global_system_risk(report_data)
    
    #========================================== PASO 11: EVALUACION DE ESCENARIOS DE CONTRAMEDIDAS PARA EL PROBLEMA DE OPTIMIZACION =========================================#
    print("\n" + "="*80)
    print("PASO 11: EVALUACION DE ESCENARIOS DE CONTRAMEDIDAS PARA EL PROBLEMA DE OPTIMIZACION")
    print("="*80)
    
    # Extrae las contramedidas candidatas del diagrama de influencia para cada incidente
    report_data = report.generate_incident_scenarios(report_data)
    print("\nEscenarios de incidente generados correctamente")
    
    # Genera todas las combinaciones de escenarios posibles para cada activo
    report_data = report.generate_asset_scenario_combinations(report_data)
    print("Combinaciones de escenarios por activo generadas correctamente")
    
   
    
    
    
    print(f"\nEstructura inicial del reporte: {report_data}")
    
    report.export_report_to_json(report_data)
    
    
#=================================[ENTRY_POINT]===========================================#    
if __name__ == "__main__":
    main()