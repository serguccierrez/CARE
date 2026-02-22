#========================================[IMPORTS]============================================#
import random

import pyagrum as gum
import json
import numpy as np
from pathlib import Path
from scipy.stats import entropy


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

MITRE_TACTICS = [
    "Reconnaissance",
    "Resource Development",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact"
]
#========================================[ID DEFINITION]========================================#
def make_lvar(name, desc, states):
    """
    Función utilizada para crear las variables labelizadas de los nodos del diagrama de influencia.
    """
    v = gum.LabelizedVariable(name, desc, len(states))
    for i, s in enumerate(states):
        v.changeLabel(i, s)
    return v


def create_and_solve_dimension(dimension_name, node_name, tactic):
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
    cm = ID.addDecisionNode(make_lvar("CM", "Countermeasure", CPDS["CM"]["states"]))
    threat = ID.addChanceNode(make_lvar("Threat", "Threat", CPDS["Threat"]["states"]))
    risk = ID.addChanceNode(make_lvar("Risk", "Risk", CPDS["Risk_given_Threat_by_tactic"]["states"]))
    res = ID.addChanceNode(make_lvar(node_name, f"Residual {dimension_name}", CPDS[node_name]["states"]))
    utility = ID.addUtilityNode(gum.LabelizedVariable(f"U_{dimension_name}", f"Utility {dimension_name}", 1))
    
    #=================={Definición de arcos (dependencias)}========================#
    ID.addArc(threat, risk)
    ID.addArc(risk, res)
    ID.addArc(cm, res)
    ID.addArc(res, utility)
    
    #=================={Asignación de distribuciones de probabilidad}========================#
    ID.cpt(threat)[{}] = [1 - confidence, confidence]
    
    # Usar distribución en función de la táctica para Risk (por tácticas MITRE en bn_CPDs.json)
    risk_dist = CPDS["Risk_given_Threat_by_tactic"][tactic]["values"]
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
    ie = gum.ShaferShenoyLIMIDInference(ID) # Cargaomos el motor de inferencia
    ie.makeInference()
    
    return ID, ie
    
#====================[EXTRACCIÓN DE UTILIDAD ESPERADA POR CM Y VECTOR DE PROBS DE TOMA DE DECISIÓN]========================#
def softmax(x, T=1.0):
    """
    Convierte un vector de utilidades o logits en una distribución de probabilidad normalizada. (distribución de preferencia)
        
    Utiliza la función softmax con parámetro de temperatura (T) para controlar la "suavidad"
    de la distribución resultante. Un valor de T bajo hace la distribución más afilada (one-hot),
    mientras que un valor de T alto hace la distribución más uniforme.
    
    Args:
        x (list o array): Vector de valores (utilidades, logits, o scores) a normalizar.
        T (float): Parámetro de temperatura que controla la distribución. Default: 1.0 (softmax estándar).
        
    Returns:
        np.array: Distribución de probabilidades normalizada en el rango [0, 1] que suma a 1.
    """
    # Convertir a array numpy de precisión doble para evitar problemas de overflow numérico
    x = np.array(x, dtype=np.float64)
    # Restar el máximo para estabilidad numérica (evita exponenciales muy grandes que causen overflow)
    shifted = (x - np.max(x)) / T
    # Calcular exponencial de los valores normalizados
    exp_x = np.exp(shifted)
    # Normalizar dividiendo por la suma para obtener probabilidades válidas
    return exp_x / np.sum(exp_x)


def expected_utility_per_cm(influence_diagram):
    """
    Calcula EU(CM=estado) probando cada contramedida por separado.
    Devuelve:
      - EU_by_cm: lista de utilidades esperadas (una por CM)
      - p_cm: soft policy (softmax de EU_by_cm)
    """
    EU_by_cm = []

    for cm_state in CPDS["CM"]["states"]:
        ie_tmp = gum.ShaferShenoyLIMIDInference(influence_diagram)

        # Fijamos la decisión CM a un estado concreto
        ie_tmp.addEvidence("CM", cm_state)

        ie_tmp.makeInference()

        EU_by_cm.append(float(ie_tmp.MEU()["mean"]))

    p_cm = softmax(EU_by_cm)
    h = entropy(p_cm, base=len(p_cm))  
    return EU_by_cm, p_cm, h

#========================================[INFERENCIA PARA CADA DIMENSIÓN CIA]========================================#
choice = random.choice(MITRE_TACTICS)
print(f"Construyendo diagrama de influencia para táctica: {choice}")

# Crear soluciones para cada dimensión
influence_diagram_C, ie_C = create_and_solve_dimension("C", "C_res", choice)
influence_diagram_I, ie_I= create_and_solve_dimension("I", "I_res", choice)
influence_diagram_A, ie_A = create_and_solve_dimension("A", "A_res", choice)

# Para cada dimensión
optimal_cm_C = ie_C.optimalDecision("CM")
optimal_cm_I = ie_I.optimalDecision("CM")
optimal_cm_A = ie_A.optimalDecision("CM")

# Calcular EU por CM para cada dimensión
EU_by_cm_C, p_cm_C, h_C = expected_utility_per_cm(influence_diagram_C)
EU_by_cm_I, p_cm_I, h_I = expected_utility_per_cm(influence_diagram_I)
EU_by_cm_A, p_cm_A, h_A = expected_utility_per_cm(influence_diagram_A)

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
