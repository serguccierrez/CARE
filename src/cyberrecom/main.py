#=============================[IMPORTS]===========================================#
import random
import networkx as nx
from pathlib import Path

import src.database.load_data as load_data
import src.cyberrecom.mitre as mitre
import src.graph.grafo as grafo
import src.database.create_db as create_db



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
    
    
    load_data.load_and_insert_data(EXCEL_PATH, DB_PATH)
    
    
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
    
    print(f"\nSimulación de amenaza: TTP={random_threat_vector['ttp_id']}, Confidence={random_threat_vector['confidence']:.2f}, Asset={random_threat_vector['asset']}, Tactic={random_threat_vector['tactic']}")
  
    
    # ============ PASO 5: Analizar impacto en el grafo MDO ============
    print("\n" + "="*80)
    print("PASO 5: ANALIZAR IMPACTO EN EL GRAFO MDO")
    print("="*80)
    
    affected_nodes, affected_edges = grafo.get_infected_nodes(G_global, random_threat_vector['asset'])
    affected_edges =grafo.get_dependency_probs_by_tactic(ttp_tactic, affected_edges)
    
    for level, nodes in affected_nodes.items():
        print(f"Nivel {level}: {nodes}")
        
    for level, edges in affected_edges.items():
        print(f"Nivel {level} - Aristas afectadas: {edges}")
    
    
    # ============ PASO 6: Construcción de la red de bayes para el activo atacado ============
    red_bayes_model = red_bayes.bayesian_network_construction(ttp_tactic)
    
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
    influence_diagram_C, ie_C = id_test.create_and_solve_dimension("C", "C_res", ttp_tactic)
    influence_diagram_I, ie_I = id_test.create_and_solve_dimension("I", "I_res", ttp_tactic)
    influence_diagram_A, ie_A = id_test.create_and_solve_dimension("A", "A_res", ttp_tactic)
    
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
    if len(affected_nodes) > 1:
        for index in range(len(affected_nodes)) :
            prob_threat_next_asset = red_bayes.get_res_threat_prob(affected_edges, random_threat_vector['confidence'], index, ttp_tactic)
            print(f"Nivel {index}: Threat Probability = {prob_threat_next_asset}")



#=================================[ENTRY_POINT]===========================================#    
if __name__ == "__main__":
    main()