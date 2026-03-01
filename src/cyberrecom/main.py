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
    
    random_asset = random.choice(list(G_global.nodes))
    random_threat_vector = mitre.ttp_simulation()
    ttp_tactic = mitre.get_ttp_details_from_ttp_id(random_threat_vector['ttp_id'])
    random_threat_vector['asset'] = random_asset
    random_threat_vector['tactic'] = ttp_tactic
    
    print(f"\nSimulación de amenaza: TTP={random_threat_vector['ttp_id']}, Confidence={random_threat_vector['confidence']:.5f}, Asset={random_threat_vector['asset']}, Tactic={random_threat_vector['tactic']}")
  
  
    #{Inicializo JSON de reporte}
    report_data = report.initialize_simulation_data(random_threat_vector)
    
    # ============ PASO 5: Analizar impacto en el grafo MDO ============
    print("\n" + "="*80)
    print("PASO 5: ANALIZAR IMPACTO EN EL GRAFO MDO")
    print("="*80)
    
    affected_nodes, affected_edges = grafo.get_infected_nodes(G_global, random_threat_vector['asset'])
    affected_edges =grafo.get_dependency_probs_by_tactic(ttp_tactic, affected_edges)
    
    #{Añado nodos y aristas afectadas al reporte}
    report_data = report.include_affected_nodes_and_edges(report_data, affected_nodes, affected_edges)
    
    for level, nodes in affected_nodes.items():
        print(f"Nivel {level}: {nodes}")
        
    for level, edges in affected_edges.items():
        print(f"Nivel {level} - Aristas afectadas: {edges}")
    
    
    # ============ PASO 6: Construcción de la red de bayes para el activo atacado ============
    red_bayes_model = red_bayes.bayesian_network_construction(ttp_tactic,random_threat_vector['confidence'])
    
    #DEBUG
    #pregunta: P(Threat)?
    threat_prob = red_bayes_model.query(variables=["Threat"])
    print(f"\nP(Threat):")
    print(threat_prob)
    
    # Pregunta: ¿Cuál es C_res si aplico firewall?
    c_res = red_bayes_model.query(variables=["C_res"], evidence={"CM": "none"})
    print("\nP(C_res | CM=none):")
    print(c_res)
    c_res_levels = red_bayes.get_cia_res_levels(c_res)
    
    # Pregunta: ¿Cuál es I_res si aplico firewall?
    i_res = red_bayes_model.query(variables=["I_res"], evidence={"CM": "none"})
    print("\nP(I_res | CM=none):")
    print(i_res)
    i_res_levels = red_bayes.get_cia_res_levels(i_res)

    # Pregunta: ¿Cuál es A_res si aplico firewall?
    a_res = red_bayes_model.query(variables=["A_res"], evidence={"CM": "none"})
    print("\nP(A_res | CM=none):")
    print(a_res)
    a_res_levels = red_bayes.get_cia_res_levels(a_res)
    
    # ================ PASO 7: Construcción y resolución de diagramas de influencia para cada dimensión CIA ===============
    influence_diagram_C, ie_C = id_test.create_and_solve_dimension("C", "C_res", ttp_tactic, random_threat_vector['confidence'])
    influence_diagram_I, ie_I = id_test.create_and_solve_dimension("I", "I_res", ttp_tactic, random_threat_vector['confidence'])
    influence_diagram_A, ie_A = id_test.create_and_solve_dimension("A", "A_res", ttp_tactic, random_threat_vector['confidence'])
    
    # Para cada dimensión
    optimal_cm_C = ie_C.optimalDecision("CM")
    optimal_cm_I = ie_I.optimalDecision("CM")
    optimal_cm_A = ie_A.optimalDecision("CM")

    # Calcular EU por CM para cada dimensión
    EU_by_cm_C, p_cm_C, h_C = id_test.expected_utility_per_cm(influence_diagram_C)
    EU_by_cm_I, p_cm_I, h_I = id_test.expected_utility_per_cm(influence_diagram_I)
    EU_by_cm_A, p_cm_A, h_A = id_test.expected_utility_per_cm(influence_diagram_A)
    
    

    
    
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
    
   
   #========================================= PASO 8: Calculo del Threat del siguiente activo dependiente =========================================#
    print("\n" + "="*80)
    print("PASO 8: CALCULO DEL THREAT DEL SIGUIENTE ACTIVO DEPENDIENTE")
    print("="*80)
    
   
   
    affected_nodes_with_threat_prob = red_bayes.get_res_threat_prob(affected_edges, random_threat_vector['confidence'], ttp_tactic, affected_nodes)
        
    if len(affected_nodes) > 1:
        print("\nProbabilidades de P(Threat) = yes, para nodos afectados en el siguiente nivel:")
        
        for level, nodes_info in affected_nodes_with_threat_prob.items():
            print(f"Nivel {level}:")
            for node_info in nodes_info:
                print(f"  Nodo: {node_info['node']}, P(Threat)={node_info['probability_(Threat)']:.4f}")
                
                
    #========================================= PASO 9: Construcción de la red de bayes para el siguiente nivel y de los diagramas de influencia =========================================#
    print("\n" + "="*80)
    print("PASO 9: CONSTRUCCIÓN DE LA RED DE BAYES PARA EL SIGUIENTE NIVEL Y DE LOS DIAGRAMAS DE INFLUENCIA")
    print("="*80)

    #{Cargamos sus datos en el JSON de reporte}
    report_data = report.include_levels_analysis(report_data, affected_nodes_with_threat_prob, affected_nodes[0], affected_nodes_with_threat_prob[0][0]['probability_(Threat)'], c_res_levels, i_res_levels, a_res_levels, str(optimal_cm_C), str(optimal_cm_I), str(optimal_cm_A), EU_by_cm_C, EU_by_cm_I, EU_by_cm_A, p_cm_C, p_cm_I, p_cm_A, level=0)
    
    if len(affected_nodes) > 1:
        for level, infected_nodes in affected_nodes_with_threat_prob.items():
            if level == 0:
                continue  # El nivel 0 es el nodo raíz, ya lo procesamos en el paso anterior
            
            print(f"\nConstruyendo red de bayes para nivel {level}")
            
            
            for node in infected_nodes:
                
                #{Construcción de la red de bayes para cada nodo infectado en este nivel}
                print(f"  Nodo: {node['node']}, P(Threat)={node['probability_(Threat)']:.5f}")
                bn = red_bayes.bayesian_network_construction(ttp_tactic, node['probability_(Threat)'])
                
                #DEBUG
                #pregunta: P(Threat)?
                threat_prob = bn.query(variables=["Threat"])
                print(f"\nP(Threat):")
                print(threat_prob)
                
                # Pregunta: ¿Cuál es C_res si aplico firewall?
                c_res = bn.query(variables=["C_res"], evidence={"CM": "none"})
                print("\nP(C_res | CM=none):")
                print(c_res)
                c_res_levels = red_bayes.get_cia_res_levels(c_res)
                
                # Pregunta: ¿Cuál es I_res si aplico firewall?
                i_res = bn.query(variables=["I_res"], evidence={"CM": "none"})
                print("\nP(I_res | CM=none):")
                print(i_res)
                i_res_levels = red_bayes.get_cia_res_levels(i_res)

                # Pregunta: ¿Cuál es A_res si aplico firewall?
                a_res = bn.query(variables=["A_res"], evidence={"CM": "none"})
                print("\nP(A_res | CM=none):")
                print(a_res)
                a_res_levels = red_bayes.get_cia_res_levels(a_res)
                
                
                #{Construcción y resolución de diagramas de influencia para cada dimensión CIA}
                influence_diagram_C, ie_C = id_test.create_and_solve_dimension("C", "C_res", ttp_tactic, node['probability_(Threat)'])
                influence_diagram_I, ie_I = id_test.create_and_solve_dimension("I", "I_res", ttp_tactic, node['probability_(Threat)'])
                influence_diagram_A, ie_A = id_test.create_and_solve_dimension("A", "A_res", ttp_tactic, node['probability_(Threat)'])
                
                # Para cada dimensión
                optimal_cm_C = ie_C.optimalDecision("CM")
                optimal_cm_I = ie_I.optimalDecision("CM")
                optimal_cm_A = ie_A.optimalDecision("CM")

                # Calcular EU por CM para cada dimensión
                EU_by_cm_C, p_cm_C, h_C = id_test.expected_utility_per_cm(influence_diagram_C)
                EU_by_cm_I, p_cm_I, h_I = id_test.expected_utility_per_cm(influence_diagram_I)
                EU_by_cm_A, p_cm_A, h_A = id_test.expected_utility_per_cm(influence_diagram_A)
                
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
                
                #{Cargamos sus datos en el JSON de reporte}
                report_data = report.include_levels_analysis(report_data, affected_nodes_with_threat_prob, node['node'], node['probability_(Threat)'], c_res_levels, i_res_levels, a_res_levels, str(optimal_cm_C), str(optimal_cm_I), str(optimal_cm_A), EU_by_cm_C, EU_by_cm_I, EU_by_cm_A, p_cm_C, p_cm_I, p_cm_A, level)

                
    #========================================= PASO 10: exporte a JSON =========================================#    
    print("\n" + "="*80)
    print("PASO 10: EXPORTE A JSON")
    print("="*80)
        # Aquí se implementaría la lógica para exportar los resultados a JSON, incluyendo:
        #metadatos de la simulación (fecha, hora, etc.) --> var simulation_metadata
        # - Detalles de la amenaza simulada (TTP, activo afectado, etc.) --> var random_threat_vector
        # - Nodos y aristas afectados en el grafo MDO --> var affected_nodes, affected_edges, affected_nodes_with_threat_prob
        # - Resultados de las consultas a la red de bayes para cada nodo afectado ---> crear una variable para guardar los resultados de cada nodo
        # - Resultados de los diagramas de influencia para cada nodo afectado --> crear una variable para guardar los resultados de cada nodo
               
        #{Creamos la estructura de datos para exportar a JSON}
        
        
    
    #{Exportamos a JSON el reporte de la simulación}
    reporting_path = Path(__file__).parent.parent / "reporting"
    reporting_path.mkdir(exist_ok=True)
    with open(reporting_path / "report.json", "w") as f:
        json.dump(report_data, f, indent=2)

'''
    print('prueba de que contienen las variables:')
    print(f"random_threat_vector: {random_threat_vector}")        
    print(f"affected_nodes: {affected_nodes}")
    print(f"affected_edges: {affected_edges}")
    print(f"affected_nodes_with_threat_prob: {affected_nodes_with_threat_prob}")
    print(f"a_res_levels: {a_res_levels}")
    print(f"EU_by_cm_A: {EU_by_cm_A}")
    print(f"h_A: {h_A}")
    string_to_print = f"optimal_cm_C: str({optimal_cm_C})"
    print(string_to_print)
    print(f"EU_by_cm_C: {EU_by_cm_C}")
    print(f"h_C: {h_C}")
'''

#=================================[ENTRY_POINT]===========================================#    
if __name__ == "__main__":
    main()