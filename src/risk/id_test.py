#========================================[IMPORTS]============================================#
import pyagrum as gum
import json
from pathlib import Path


#=============================[JSON READING]===========================================#
def read_constants():
    with open(Path(__file__).parent.parent.parent / "configs" / "bn_CPDs.json", "r") as f:
        return json.load(f)
    
def read_impact_levels():
    with open(Path(__file__).parent.parent.parent / "configs" / "constants.json", "r") as f:
        return json.load(f)["impact_levels"]


#=============================[CONSTANTS]===========================================#
CPDS = read_constants()
IMPACT_LEVELS = read_impact_levels()
confidence = 0.8
#========================================[ID DEFINITION]========================================#
def make_lvar(name, desc, states):
    """
    Función utilizada para crear las variables labelizadas de los nodos del diagrama de influencia.
    """
    v = gum.LabelizedVariable(name, desc, len(states))
    for i, s in enumerate(states):
        v.changeLabel(i, s)
    return v


def create_and_solve_dimension(dimension_name, node_name, display_name):
    """
    Crea un diagrama de influencia para una dimensión CIA (Confidentiality, Integrity, Availability)
    y lo resuelve para encontrar la contramedida (CM) óptima que minimice el impacto residual.
    
    El diagrama sigue la estructura:
        Threat -> Risk -> Residual_Impact <- CM -> Utility
    
    Args:
        dimension_name (str): Letra de la dimensión ("C", "I" o "A") para la utilidad y labels
        node_name (str): Nombre del nodo residual ("C_res", "I_res" o "A_res")
        display_name (str): Nombre legible para imprimir ("CONFIDENTIALITY", "INTEGRITY", "AVAILABILITY")
    
    Returns:
        tuple: (inference_engine, decision_node) donde:
            - inference_engine: objeto de inferencia con la solución del diagrama
            - decision_node: nodo de decisión CM del diagrama
    """
    #=================={Inicialización diagrama de influencia y nodos}========================#
    ID = gum.InfluenceDiagram()
    
    # Nodos
    CM = ID.addDecisionNode(make_lvar("CM", "Countermeasure", CPDS["CM"]["states"]))
    threat = ID.addChanceNode(make_lvar("Threat", "Threat", CPDS["Threat"]["states"]))
    risk = ID.addChanceNode(make_lvar("Risk", "Risk", CPDS["Risk_given_Threat_by_tactic"]["states"]))
    res = ID.addChanceNode(make_lvar(node_name, f"Residual {dimension_name}", CPDS[node_name]["states"]))
    utility = ID.addUtilityNode(gum.LabelizedVariable(f"U_{dimension_name}", f"Utility {dimension_name}", 1))
    
    #=================={Definición de arcos (dependencias)}========================#
    ID.addArc(threat, risk)
    ID.addArc(risk, res)
    ID.addArc(CM, res)
    ID.addArc(res, utility)
    
    #=================={Asignación de distribuciones de probabilidad}========================#
    ID.cpt(threat)[{}] = [1 - confidence, confidence]
    
    # Usar distribución por defecto para Risk (por tácticas MITRE en bn_CPDs.json)
    risk_dist = CPDS["Risk_given_Threat_by_tactic"]["default"]["values"]
    for t_idx, t_lab in enumerate(CPDS["Threat"]["states"]):
        dist = [risk_dist[r_idx][t_idx] for r_idx in range(len(CPDS["Risk_given_Threat_by_tactic"]["states"]))]
        ID.cpt(risk)[{"Threat": t_lab}] = dist
    
    col = 0
    for r in CPDS["Risk_given_Threat_by_tactic"]["states"]:
        for cm in CPDS["CM"]["states"]:
            dist = [CPDS[node_name]["values"][i][col] for i in range(len(CPDS[node_name]["states"]))]
            ID.cpt(res)[{"Risk": r, "CM": cm}] = dist
            col += 1
    
    #=================={Asignación de valores de utilidad}========================#
    for state in CPDS[node_name]["states"]:
        ID.utility(utility)[{node_name: state}] = -IMPACT_LEVELS[state]
    
    #=================={Inferencia y obtención de decisión óptima}========================#
    ie = gum.ShaferShenoyLIMIDInference(ID)
    ie.makeInference()
    
    print(f"\n=== {display_name} ===")
    print(f"MEU: {ie.MEU()}")
    print(f"Optimal decision: {ie.optimalDecision(CM)}")
    
    return ie, CM

#========================================[INFERENCIA PARA CADA DIMENSIÓN CIA]========================================#
# Crear soluciones para cada dimensión
ie_C, _ = create_and_solve_dimension("C", "C_res", "CONFIDENTIALITY")
ie_I, _ = create_and_solve_dimension("I", "I_res", "INTEGRITY")
ie_A, _ = create_and_solve_dimension("A", "A_res", "AVAILABILITY")
