"""
Se construyen y resuelven diagramas de influencia para evaluar contramedidas.
Se calculan utilidades esperadas por dimensión CIA a partir de CPDs y tácticas MITRE.
"""

#========================================[IMPORTS]============================================#
import random

import pyagrum as gum
import json
import numpy as np
from pathlib import Path
from scipy.stats import entropy


#=============================[JSON READING]===========================================#
def read_constants():
    """
    Lee las CPDs utilizadas por los diagramas de influencia.

    Args:
        None.

    Returns:
        Diccionario con las distribuciones de probabilidad cargadas desde JSON.
    """
    with open(Path(__file__).parent.parent.parent / "configs" / "bn_CPDs.json", "r") as f:
        return json.load(f)
    
def read_impact_levels():
    """
    Lee los niveles de impacto definidos en la configuración general.

    Args:
        None.

    Returns:
        Diccionario con los niveles de impacto por estado.
    """
    with open(Path(__file__).parent.parent.parent / "configs" / "constants.json", "r") as f:
        return json.load(f)["impact_levels"]


#=============================[CONSTANTS]===========================================#
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
    Crea una variable labelizada para los nodos del diagrama de influencia.

    Args:
        name: Nombre interno de la variable.
        desc: Descripción legible de la variable.
        states: Lista de estados posibles.

    Returns:
        Variable labelizada de pyAgrum con los estados indicados.
    """
    v = gum.LabelizedVariable(name, desc, len(states))
    for i, s in enumerate(states):
        v.changeLabel(i, s)
    return v


def create_and_solve_dimension(dimension_name, node_name, tactic, confidence, CPDS):
    """
    Crea y resuelve un diagrama de influencia para una dimensión CIA.
    Se modelan amenaza, riesgo, contramedida, impacto residual y utilidad.
    
    El diagrama sigue la estructura:
        Threat -> Risk -> Residual_Impact <- CM -> Utility
    
    Args:
        dimension_name: Letra de la dimensión CIA ("C", "I" o "A").
        node_name: Nombre del nodo de impacto residual asociado a la dimensión.
        tactic: Táctica MITRE utilizada para seleccionar la distribución de riesgo.
        confidence: Confianza asociada a la presencia de la amenaza.
        CPDS: Diccionario con las distribuciones de probabilidad del modelo.
    
    Returns:
        Tuple con el diagrama de influencia y el motor de inferencia resuelto.
    """
    # Se inicializa el diagrama de influencia y sus nodos principales
    ID = gum.InfluenceDiagram()
    
    
    
    cm = ID.addDecisionNode(make_lvar("CM", "Countermeasure", CPDS["CM"]["states"]))
    threat = ID.addChanceNode(make_lvar("Threat", "Threat", CPDS["Threat"]["states"]))
    risk = ID.addChanceNode(make_lvar("Risk", "Risk", CPDS["Risk_given_Threat_by_tactic"]["states"]))
    res = ID.addChanceNode(make_lvar(node_name, f"Residual {dimension_name}", CPDS[node_name]["states"]))
    utility = ID.addUtilityNode(gum.LabelizedVariable(f"U_{dimension_name}", f"Utility {dimension_name}", 1))
    
    # Se definen las dependencias entre nodos del diagrama
    ID.addArc(threat, risk)
    ID.addArc(risk, res)
    ID.addArc(cm, res)
    ID.addArc(res, utility)
    
    # Se asignan distribuciones de probabilidad condicionadas por táctica y contramedida
    ID.cpt(threat)[{}] = [1 - confidence, confidence]
    
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
    
    # Se asigna utilidad negativa según el impacto residual
    for state in CPDS[node_name]["states"]:
        ID.utility(utility)[{node_name: state}] = -IMPACT_LEVELS[state]
    
    # Se ejecuta inferencia para obtener la política óptima
    ie = gum.ShaferShenoyLIMIDInference(ID)
    ie.makeInference()
    
    return ID, ie
    
#====================[EXTRACCIÓN DE UTILIDAD ESPERADA POR CM Y VECTOR DE PROBS DE TOMA DE DECISIÓN]========================#
def softmax(x, T=1.0):
    """
    Convierte un vector de utilidades o logits en una distribución de probabilidad.
        
    Se usa una temperatura T para controlar si la distribución queda más concentrada o uniforme.
    
    Args:
        x: Vector de valores a normalizar.
        T: Parámetro de temperatura de la distribución.
        
    Returns:
        Distribución de probabilidades normalizada.
    """
    # Se estabiliza numéricamente el cálculo antes de aplicar exponenciales
    x = np.array(x, dtype=np.float64)
    shifted = (x - np.max(x)) / T
    exp_x = np.exp(shifted)
    return exp_x / np.sum(exp_x)


def expected_utility_per_cm(influence_diagram, cpds):
    """
    Calcula EU(CM=estado) probando cada contramedida por separado.
    Se obtiene también una política probabilística mediante softmax y su entropía.

    Args:
        influence_diagram: Diagrama de influencia que se va a evaluar.
        cpds: Diccionario con estados y distribuciones del modelo.

    Returns:
        Tuple con utilidades esperadas, política softmax y entropía normalizada.
    """
    EU_by_cm = []

    for cm_state in cpds["CM"]["states"]:
        ie_tmp = gum.ShaferShenoyLIMIDInference(influence_diagram)

        # Se fija la decisión a una contramedida concreta para evaluar su utilidad
        ie_tmp.addEvidence("CM", cm_state)

        ie_tmp.makeInference()

        EU_by_cm.append(float(ie_tmp.MEU()["mean"]))

    p_cm = softmax(EU_by_cm)
    h = entropy(p_cm, base=len(p_cm))  
    return EU_by_cm, p_cm, h

#========================================[INFERENCIA PARA CADA DIMENSIÓN CIA]========================================#
def test_id():
    """
    Ejecuta una prueba manual de inferencia para una táctica MITRE aleatoria.
    Se resuelven las dimensiones C, I y A y se muestran utilidades por contramedida.

    Args:
        None.

    Returns:
        None. Se imprimen por consola las decisiones y utilidades calculadas.
    """
    
    CPDS = read_constants()
    
    choice = random.choice(MITRE_TACTICS)
    print(f"Construyendo diagrama de influencia para táctica: {choice}")

    # Se crean y resuelven diagramas para cada dimensión CIA
    influence_diagram_C, ie_C = create_and_solve_dimension("C", "C_res", choice, confidence=0.8, CPDS=CPDS)
    influence_diagram_I, ie_I= create_and_solve_dimension("I", "I_res", choice, confidence=0.8, CPDS=CPDS)
    influence_diagram_A, ie_A = create_and_solve_dimension("A", "A_res", choice, confidence=0.8, CPDS=CPDS)

    # Se extraen las contramedidas óptimas por dimensión
    optimal_cm_C = ie_C.optimalDecision("CM")
    optimal_cm_I = ie_I.optimalDecision("CM")
    optimal_cm_A = ie_A.optimalDecision("CM")

    # Se calculan utilidades esperadas y políticas softmax por contramedida
    EU_by_cm_C, p_cm_C, h_C = expected_utility_per_cm(influence_diagram_C,cpds=CPDS)
    EU_by_cm_I, p_cm_I, h_I = expected_utility_per_cm(influence_diagram_I,cpds=CPDS)
    EU_by_cm_A, p_cm_A, h_A = expected_utility_per_cm(influence_diagram_A,cpds=CPDS)

    # Se muestran los resultados de la prueba por consola
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
