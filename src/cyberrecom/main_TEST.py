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
    
    res_threat_prob = red_bayes.get_res_threat_prob(affected_edges, affected_nodes, random_threat_vectors)
    print(f"\nProbabilidades de amenaza calculadas para los activos afectados: {res_threat_prob}")
    
    
    #========================================== PASO 9: red de bayes para activos =========================================#
    
    for ttp_id, threat_vector in random_threat_vectors.items():
        for asset, info_asset in res_threat_prob.items():
            print(f"\nCalculando red de Bayes para TTP {ttp_id} - Asset {asset}...")
            
            # Crear modelo de red bayesiana con tactic y confidence del asset
            red_bayes_model = red_bayes.bayesian_network_construction(threat_vector['tactic'], info_asset['P(Threat)'])
            print(f"Red de Bayes construida para TTP {ttp_id}")
            
            # Realizar queries
            threat_prob = red_bayes_model.query(variables=["Threat"])
            c_res = red_bayes_model.query(variables=["C_res"], evidence={"CM": "none"})
            c_res_levels = red_bayes.get_cia_res_levels(c_res)
            
            i_res = red_bayes_model.query(variables=["I_res"], evidence={"CM": "none"})
            i_res_levels = red_bayes.get_cia_res_levels(i_res)
            
            a_res = red_bayes_model.query(variables=["A_res"], evidence={"CM": "none"})
            a_res_levels = red_bayes.get_cia_res_levels(a_res)
            
            # Agregar modelo y resultados de inferencia al asset
            info_asset['bayesian_network_inference'] = {
                'queries': {
                    'c_res_levels': c_res_levels,
                    'i_res_levels': i_res_levels,
                    'a_res_levels': a_res_levels
                }
            }
            
            print(f"Inferencia almacenada para {asset}")
            print(f"P(C_res | CM=none): {c_res_levels}")
            print(f"P(I_res | CM=none): {i_res_levels}")
            print(f"P(A_res | CM=none): {a_res_levels}")
    
        report_data = report.include_node_analysis(report_data, res_threat_prob)
        
            
    
    
    
    
    
    
    
                
   
    
   
    
    print(f"\nEstructura inicial del reporte: {report_data}")
    
     #{Exportamos a JSON el reporte de la simulación}
    reporting_path = Path(__file__).parent.parent / "reporting"
    reporting_path.mkdir(exist_ok=True)
    with open(reporting_path / "report.json", "w", encoding="utf-8") as f:
        json.dump(report_data, f, indent=2, ensure_ascii=False)
    
    
#=================================[ENTRY_POINT]===========================================#    
if __name__ == "__main__":
    main()