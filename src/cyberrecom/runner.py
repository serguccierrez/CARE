"""
Se orquesta el flujo principal de análisis CARE sobre un escenario seleccionado.
Se construye el grafo, se resuelven amenazas, inferencias, reporte de riesgo y optimización.
"""

#=============================[IMPORTS]===========================================#
from datetime import datetime
import copy
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

import src.risk.optimization as optimization

#=============================[CONSTANTS]===========================================#
#DB_PATH = Path(__file__).parent.parent / "database" / "tfg_catalog_v1.0.0.db"
DB_PATH = Path(__file__).parent.parent / "database" / "tfg_catalog.db"
EXCEL_PATH = Path(__file__).parent.parent.parent / "data" / "asset_catalog_validado_v1.0.0_ajustado.xlsx"
BASE_CM_STATES = ["none"]



#==============================[AUXILIARY FUNCTIONS]===========================================#
def load_report_data_from_json(json_path=None):
    """
    Carga desde JSON el reporte de riesgo generado previamente.

    Args:
        json_path: Ruta opcional del archivo de reporte. Si no se indica, se usa report.json.

    Returns:
        Diccionario con los datos del reporte.
    """
    if json_path is None:
        json_path = Path(__file__).parent.parent / "reporting" / "report.json"
    with open(json_path, 'r') as f:
        report_data = json.load(f)
    return report_data

#==============================[MAIN FUNCTION]===========================================#


def resolve_scenario(scenario_name: str) -> None:
    """
    Construye el grafo MDO global para el escenario indicado.

    Args:
        scenario_name: Nombre del escenario que se desea analizar.

    Returns:
        Grafo global construido a partir de la base de datos.
    """
    G_global = grafo.build_MDO_graph(str(DB_PATH), scenario_name )
    
    return G_global


def _ensure_list(value):
    """
    Normaliza un valor para tratarlo siempre como lista.

    Args:
        value: Valor individual, lista o None.

    Returns:
        Lista equivalente al valor recibido.
    """
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]
    
def resolve_threat_vector(G_global, context) -> None:
    """
    Resuelve los vectores de amenaza que se aplican sobre el grafo.
    Se permite modo aleatorio o selección explícita desde el contexto de ejecución.

    Args:
        G_global: Grafo global del escenario analizado.
        context: Diccionario con modo, activos, TTPs y confianzas seleccionadas.

    Returns:
        Tuple con vectores de amenaza y estructura inicial del reporte.
    """
    
    mode = context["mode"]
    selected_assets = _ensure_list(context.get("selected_asset"))
    selected_ttps = _ensure_list(context.get("selected_ttps"))
    selected_confidences = _ensure_list(context.get("selected_confidences"))
    
    if mode == "random":
    
        # Se simulan TTPs aleatorias válidas y se asigna un activo afectado a cada una
        threat_vectors = mitre.ttp_simulation()  # Es un diccionario con keys 'ttp_id' y 'confidence' (puede haber más de un TTP)
        
        for ttp_id, threat_vector in threat_vectors.items():
            random_asset = random.choice(list(G_global.nodes))
            print(threat_vector)
            confidence = threat_vector['confidence']
            ttp_tactic = threat_vector['tactic']
            threat_vector['asset'] = random_asset
            
            print(f"\nSimulación de amenaza: TTP={ttp_id}, Confidence={confidence:.5f}, Asset={random_asset}, Tactic={ttp_tactic}")
    
    else:
        # Se construyen vectores de amenaza a partir de selecciones explícitas o valores por defecto
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
                ttp_name = ttp.get("name") or mitre.get_ttp_name_from_ttp_id(ttp_id)
                ttp_details = ttp.get("tactic") or mitre.get_ttp_details_from_ttp_id(ttp_id)
            else:
                ttp_id = ttp
                ttp_name = mitre.get_ttp_name_from_ttp_id(ttp_id)
                ttp_details = mitre.get_ttp_details_from_ttp_id(ttp_id)

            threat_vectors[ttp_id] = {
                "name": ttp_name or "Unknown",
                "confidence": confidence,
                "tactic": ttp_details,
                "asset": asset
            }
            
    # Se inicializa el reporte con amenazas y metadatos del grafo
    report_data = report.initialize_simulation_data(
        threat_vectors,
        scenario_name=context.get("active_scenario")
    )
    report_data = report.add_graph_metadata(report_data, G_global)
    
    return threat_vectors, report_data
    
    
def resolve_graph_impact(G_global, threat_vectors, report_data):
    """
    Calcula el impacto de cada vector de amenaza sobre el grafo.
    Se obtienen nodos y aristas afectados y se propagan probabilidades de amenaza.

    Args:
        G_global: Grafo global del escenario.
        threat_vectors: Diccionario con TTPs, activos y confianzas.
        report_data: Diccionario del reporte en construcción.

    Returns:
        Tuple con probabilidades por nodo afectado y reporte actualizado.
    """
    
    # Se almacenan nodos y aristas afectados por cada TTP
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
    """
    Construye la matriz de valores residuales para una dimensión CIA.
    Se extraen columnas de riesgo bajo y alto para cada contramedida activa.

    Args:
        cm_states: Lista de contramedidas incluidas en la CPD.
        countermeasures_data: Catálogo de contramedidas con CPDs asociadas.
        dimension: Dimensión residual que se desea construir.

    Returns:
        Matriz de valores para la CPD de la dimensión indicada.
    """
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


def resolve_cm_states_for_ttps(ttp_ids, countermeasures_data, include_base_countermeasures=True):
    """
    Construye los estados de contramedida aplicables a uno o varios TTPs.

    Args:
        ttp_ids: Identificador o lista de identificadores TTP.
        countermeasures_data: Catalogo de contramedidas con CPDs asociadas.
        include_base_countermeasures: Incluye los estados base del modelo.

    Returns:
        Lista ordenada de estados CM aplicables.
    """

    ttp_ids = _ensure_list(ttp_ids)
    cm_states = []

    base_countermeasures = BASE_CM_STATES if include_base_countermeasures else ["none"]
    for base_cm_id in base_countermeasures:
        if base_cm_id in countermeasures_data["countermeasures"]:
            cm_states.append(base_cm_id)

    for ttp_id in ttp_ids:
        try:
            mitigations = mitre.get_mitigations_for_ttp(ttp_id)
        except ValueError:
            continue

        for cm in mitigations:
            cm_id = cm.get("mitigation_id")
            if (
                cm_id
                and cm_id in countermeasures_data["countermeasures"]
                and cm_id not in cm_states
            ):
                cm_states.append(cm_id)

    return cm_states


def resolve_cpds_for_cm_states(bn_cpds, countermeasures_data, cm_states):
    """
    Recalcula las CPDs residuales para un conjunto concreto de estados CM.

    Args:
        bn_cpds: Plantilla o CPDs base.
        countermeasures_data: Catalogo de contramedidas con CPDs asociadas.
        cm_states: Estados de contramedida a incluir.

    Returns:
        Copia de CPDs ajustada al conjunto CM recibido.
    """

    dynamic_bn_cpds = copy.deepcopy(bn_cpds)

    dynamic_bn_cpds["CM"]["states"] = cm_states
    dynamic_bn_cpds["CM"]["values"] = [round(1 / len(cm_states), 6) for _ in cm_states]

    dynamic_bn_cpds["C_res"]["values"] = resolve_build_res_values(cm_states, countermeasures_data, "C_res")
    dynamic_bn_cpds["I_res"]["values"] = resolve_build_res_values(cm_states, countermeasures_data, "I_res")
    dynamic_bn_cpds["A_res"]["values"] = resolve_build_res_values(cm_states, countermeasures_data, "A_res")

    return dynamic_bn_cpds


def resolve_bn_json_construction(threat_vectors):
    """
    Construye dinámicamente las CPDs activas de la red bayesiana para la simulación.
    Se combina el estado base sin mitigacion con las mitigaciones recomendadas para las TTPs analizadas.

    Args:
        threat_vectors: Diccionario con TTPs seleccionadas o simuladas.

    Returns:
        Diccionario con las CPDs dinámicas generadas.
    """
    bn_cpds_path = Path(__file__).parent.parent.parent / "configs" / "bn_CPDs_template.json"

    # Se cargan plantilla de CPDs y catálogo de contramedidas
    with open(bn_cpds_path, "r", encoding="utf-8") as f:
        bn_cpds = json.load(f)

    with open(Path(__file__).parent.parent.parent / "configs" / "countermeasures.json", "r", encoding="utf-8") as f:
        countermeasures_data = json.load(f)

    dynamic_bn_cpds = copy.deepcopy(bn_cpds)

    # Se preparan el estado base y las mitigaciones especificas de las TTPs
    raw_mitigations = []
    cm_states = []

    for base_cm_id in BASE_CM_STATES:
        if base_cm_id in countermeasures_data["countermeasures"]:
            cm_states.append(base_cm_id)

    for ttp_id, threat_vector in threat_vectors.items():
        try:
            raw_mitigations.extend(mitre.get_mitigations_for_ttp(ttp_id))
        except ValueError:
            continue

    for cm in raw_mitigations:
        cm_id = cm.get("mitigation_id")
        if (
            cm_id
            and cm_id in countermeasures_data["countermeasures"]
            and cm_id not in cm_states
        ):
            cm_states.append(cm_id)

    dynamic_bn_cpds["CM"]["states"] = cm_states
    dynamic_bn_cpds["CM"]["values"] = [round(1 / len(cm_states), 6) for _ in cm_states]

    # Se recalculan las CPDs residuales según las contramedidas activas
    dynamic_bn_cpds["C_res"]["values"] = resolve_build_res_values(cm_states, countermeasures_data, "C_res")
    dynamic_bn_cpds["I_res"]["values"] = resolve_build_res_values(cm_states, countermeasures_data, "I_res")
    dynamic_bn_cpds["A_res"]["values"] = resolve_build_res_values(cm_states, countermeasures_data, "A_res")

    # Se guarda el JSON activo que usarán red bayesiana y diagrama de influencia
    with open(Path(__file__).parent.parent.parent / "configs" / "bn_CPDs.json", "w", encoding="utf-8") as f:
        json.dump(dynamic_bn_cpds, f, indent=2, ensure_ascii=False)

    return dynamic_bn_cpds

def resolve_bn_and_id_inference(res_threat_prob, threat_vectors, report_data):
    """
    Ejecuta inferencia bayesiana y análisis con diagramas de influencia.
    Se calculan impactos residuales, contramedidas óptimas, utilidades esperadas y entropía de política.

    Args:
        res_threat_prob: Probabilidades de amenaza propagadas por activo y TTP.
        threat_vectors: Diccionario con TTPs, tácticas y activos afectados.
        report_data: Diccionario del reporte en construcción.

    Returns:
        Diccionario del reporte con análisis por nodo incorporado.
    """
    
    bn_cpds_path = Path(__file__).parent.parent.parent / "configs" / "bn_CPDs_template.json"
    countermeasures_path = Path(__file__).parent.parent.parent / "configs" / "countermeasures.json"

    with open(bn_cpds_path, "r", encoding="utf-8") as f:
        bn_cpds_template = json.load(f)

    with open(countermeasures_path, "r", encoding="utf-8") as f:
        countermeasures_data = json.load(f)

    for ttp_id, threat_vector in threat_vectors.items():
        for asset, info_asset in res_threat_prob.items():
            if ttp_id not in info_asset.get('threats_by_ttp', {}):
                continue

            print(f"Calculando red de Bayes para TTP {ttp_id} - Asset {asset}...") 


            red_bayes_model = red_bayes.bayesian_network_construction(
                threat_vector['tactic'],
                info_asset['threats_by_ttp'][ttp_id]['P(Threat)']
            )

            # Se consultan impactos residuales sin contramedida en la red bayesiana
            threat_prob = red_bayes_model.query(variables=["Threat"])
            c_res = red_bayes_model.query(variables=["C_res"], evidence={"CM": "none"})
            c_res_levels = red_bayes.get_cia_res_levels(c_res)

            i_res = red_bayes_model.query(variables=["I_res"], evidence={"CM": "none"})
            i_res_levels = red_bayes.get_cia_res_levels(i_res)

            a_res = red_bayes_model.query(variables=["A_res"], evidence={"CM": "none"})
            a_res_levels = red_bayes.get_cia_res_levels(a_res)

            # Se guardan resultados por TTP para evitar sobrescrituras entre amenazas
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


            # Se resuelven diagramas de influencia por dimensión CIA
            cm_states = resolve_cm_states_for_ttps(
                ttp_id,
                countermeasures_data,
                include_base_countermeasures=False
            )
            CPDS = resolve_cpds_for_cm_states(bn_cpds_template, countermeasures_data, cm_states)
            print(f"Contramedidas evaluadas para {asset} - {ttp_id}: {cm_states}")
            
            influence_diagram_C, ie_C = id_test.create_and_solve_dimension("C", "C_res",  threat_vector['tactic'], info_asset['threats_by_ttp'][ttp_id]['P(Threat)'], CPDS)
            influence_diagram_I, ie_I = id_test.create_and_solve_dimension("I", "I_res",  threat_vector['tactic'], info_asset['threats_by_ttp'][ttp_id]['P(Threat)'], CPDS)
            influence_diagram_A, ie_A = id_test.create_and_solve_dimension("A", "A_res",  threat_vector['tactic'], info_asset['threats_by_ttp'][ttp_id]['P(Threat)'], CPDS)

            # Se extraen contramedidas óptimas y utilidades esperadas
            optimal_cm_C = ie_C.optimalDecision("CM")
            optimal_cm_I = ie_I.optimalDecision("CM")
            optimal_cm_A = ie_A.optimalDecision("CM")

            

            EU_by_cm_C, p_cm_C, h_C = id_test.expected_utility_per_cm(influence_diagram_C, CPDS)
            EU_by_cm_I, p_cm_I, h_I = id_test.expected_utility_per_cm(influence_diagram_I, CPDS)
            EU_by_cm_A, p_cm_A, h_A = id_test.expected_utility_per_cm(influence_diagram_A, CPDS)


            # Se transforma la salida para serializarla en el reporte JSON
            best_cm_C = CPDS["CM"]["states"][EU_by_cm_C.index(max(EU_by_cm_C))]
            best_cm_I = CPDS["CM"]["states"][EU_by_cm_I.index(max(EU_by_cm_I))]
            best_cm_A = CPDS["CM"]["states"][EU_by_cm_A.index(max(EU_by_cm_A))]

            EU_by_cm_C = [abs(x) for x in EU_by_cm_C]
            EU_by_cm_I = [abs(x) for x in EU_by_cm_I]
            EU_by_cm_A = [abs(x) for x in EU_by_cm_A]


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

            
            
            # Se muestran por consola los resultados de cada dimensión
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
    """
    Calcula riesgos finales del reporte y exporta el JSON resultante.

    Args:
        report_data: Diccionario del reporte con inferencias y análisis por nodo.

    Returns:
        Diccionario del reporte con riesgos calculados.
    """
    report_data = report.calculate_incident_risk(report_data)
    report_data = report.total_risk_by_asset(report_data)
    report_data = report.calculate_global_system_risk(report_data)
    
    report.export_report_to_json(report_data)
    
    return report_data
    
def resolve_optimization(optimization_objective, budget=50000, max_time_hours=210):
    """
    Ejecuta la optimización de contramedidas sobre el último reporte generado.
    Se generan escenarios de incidente, escenarios por activo y soluciones por objetivo.

    Args:
        optimization_objective: Objetivo de optimización solicitado.
        budget: Presupuesto disponible para contramedidas.
        max_time_hours: Tiempo máximo permitido para desplegar contramedidas.

    Returns:
        Diccionario con resultados de optimización.
    """
    
    report_data = load_report_data_from_json()
    
    # Se generan escenarios necesarios para alimentar el modelo de optimización
    report_data = report.generate_incident_scenarios(report_data)
    report_data = report.generate_asset_scenario_combinations(report_data)
    
    assets_scenarios_data, decision_vars, model = optimization.setup_optimization_problem(report_data, budget)
    
    opt_results = optimization.solve_optimization_problems(assets_scenarios_data, objective_type=optimization_objective, budget=budget, max_time_hours=max_time_hours)
    
    return opt_results

def main(scenario_name, context ):
    """
    Ejecuta el flujo completo de análisis para un escenario y contexto dados.

    Args:
        scenario_name: Nombre del escenario que se analiza.
        context: Configuración de ejecución con modo, activos, TTPs y confianzas.

    Returns:
        Diccionario final del reporte generado.
    """
    
    # Se construye el grafo con el escenario seleccionado
    G_global = resolve_scenario(scenario_name)
    
    # Se construye o simula el vector de amenaza
    threat_vectors, report_data = resolve_threat_vector(G_global, context)
    
    # Se calcula el impacto en el grafo
    res_threat_prob, report_data = resolve_graph_impact(G_global, threat_vectors, report_data)

    # Se construyen CPDs dinámicas para la red bayesiana
    resolve_bn_json_construction(threat_vectors)
    
    # Se ejecuta inferencia bayesiana y análisis con diagramas de influencia
    report_data = resolve_bn_and_id_inference(res_threat_prob, threat_vectors, report_data)
    
    # Se calcula el riesgo del incidente y se exporta el reporte
    report_data = resolve_risk_assessment(report_data)
    
    return report_data

