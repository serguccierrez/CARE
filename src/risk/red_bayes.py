#========================================[IMPORTS]========================================#
from pathlib import Path
import random
from pgmpy.models import DiscreteBayesianNetwork
from pgmpy.factors.discrete import TabularCPD
from pgmpy.inference import VariableElimination

import json

#========================================[CONFIGURACIÓN]========================================#
confidence = 0.8

bn_cpds_path = Path(__file__).parent.parent.parent / "configs" / "bn_CPDs.json"
with open(bn_cpds_path, "r") as data:
    cpd_data = json.load(data)
    

#========================================[CONSTANTES]========================================#
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

#========================================[MODELO DE RED BAYESIANA]========================================#
def bayesian_network_construction(tactic="default"):
    """
    Construye un modelo de red bayesiana discreta a partir de las CPDs definidas en el archivo JSON.
    
    La red bayesiana representa las relaciones probabilísticas entre:
    - Threat: probabilidad de que haya una amenaza
    - Risk: riesgo resultante de la amenaza
    - CM: contramedida aplicada
    - C_res, I_res, A_res: impactos residuales en las tres dimensiones CIA
    
    Args:
    tactic (str): nombre de la táctica para seleccionar las CPDs específicas de riesgo dado amenaza.
    
    Returns:
        VariableElimination: motor de inferencia para realizar consultas sobre la red
    """
    
    #=================={Definición de estructura de grafo}========================#
    """
    Estructura de la red bayesiana (acíclica):
    Threat -> Risk -> C_res <- CM
                  -> I_res <- CM
                  -> A_res <- CM
    """
    model = DiscreteBayesianNetwork([
        ("Threat", "Risk"),
        ("Risk", "C_res"),
        ("Risk", "I_res"),
        ("Risk", "A_res"),
        ("CM", "C_res"),
        ("CM", "I_res"),
        ("CM", "A_res"),
    ])  
    #=================={Definición de distribuciones de probabilidad (CPDs)}========================#
    
    #--- Threat: Probabilidad de amenaza ---
    cpd_threat = TabularCPD(
        variable="Threat",
        variable_card=len(cpd_data["Threat"]["states"]),
        values=[[1 - confidence], [confidence]],
        state_names={"Threat": cpd_data["Threat"]["states"]}
    )

    #--- CM: Distribución uniforme de contramedidas ---
    cpd_cm = TabularCPD(
        variable="CM",
        variable_card=len(cpd_data["CM"]["states"]),
        values=[[p] for p in cpd_data["CM"]["values"]],
        state_names={"CM": cpd_data["CM"]["states"]}
    )

    #--- Risk: Probabilidad de riesgo dado Threat ---
    cpd_risk = TabularCPD(
        variable="Risk",
        variable_card=len(cpd_data["Risk_given_Threat_by_tactic"]["states"]),
        values=cpd_data["Risk_given_Threat_by_tactic"][tactic]["values"],
        evidence=["Threat"],
        evidence_card=[len(cpd_data["Threat"]["states"])],
        state_names={
            "Risk": cpd_data["Risk_given_Threat_by_tactic"]["states"],
            "Threat": cpd_data["Threat"]["states"]
        }
    )

    #--- C_res: Impacto residual en Confidentiality dado Risk y CM ---
    cpd_c_res = TabularCPD(
        variable="C_res",
        variable_card=len(cpd_data["C_res"]["states"]),
        values=cpd_data["C_res"]["values"],
        evidence=["Risk", "CM"],
        evidence_card=[len(cpd_data["Risk_given_Threat_by_tactic"]["states"]), len(cpd_data["CM"]["states"])],
        state_names={
            "C_res": cpd_data["C_res"]["states"],
            "Risk": cpd_data["Risk_given_Threat_by_tactic"]["states"],
            "CM": cpd_data["CM"]["states"]
        }
    )

    #--- I_res: Impacto residual en Integrity dado Risk y CM ---
    cpd_i_res = TabularCPD(
        variable="I_res",
        variable_card=len(cpd_data["I_res"]["states"]),
        values=cpd_data["I_res"]["values"],
        evidence=["Risk", "CM"],
        evidence_card=[
            len(cpd_data["Risk_given_Threat_by_tactic"]["states"]),
            len(cpd_data["CM"]["states"])
        ],
        state_names={
            "I_res": cpd_data["I_res"]["states"],
            "Risk": cpd_data["Risk_given_Threat_by_tactic"]["states"],
            "CM": cpd_data["CM"]["states"]
        }
    )

    #--- A_res: Impacto residual en Availability dado Risk y CM ---
    cpd_a_res = TabularCPD(
        variable="A_res",
        variable_card=len(cpd_data["A_res"]["states"]),
        values=cpd_data["A_res"]["values"],
        evidence=["Risk", "CM"],
        evidence_card=[
            len(cpd_data["Risk_given_Threat_by_tactic"]["states"]),
            len(cpd_data["CM"]["states"])
        ],
        state_names={
            "A_res": cpd_data["A_res"]["states"],
            "Risk": cpd_data["Risk_given_Threat_by_tactic"]["states"],
            "CM": cpd_data["CM"]["states"]
        }
    )

    #=================={Configuración e inferencia del modelo}========================#
    
    # Añadir todas las CPDs al modelo
    model.add_cpds(cpd_threat, cpd_cm, cpd_risk, cpd_c_res, cpd_i_res, cpd_a_res)

    # Validar que el modelo es correcto (consistencia de CPDs y estructura)
    assert model.check_model(), "Error: El modelo de red bayesiana no es correcto. Revisa las CPDs y la estructura del grafo."

    # Crear motor de inferencia (Variable Elimination)
    infer = VariableElimination(model)
    
    return infer


#========================================[EJEMPLOS DE CONSULTAS]========================================#
"""
# Pregunta: ¿Cuál es C_res si aplico firewall?
q1 = infer.query(variables=["C_res"], evidence={"CM": "firewall"})
print("\nP(C_res | CM=firewall):")
print(q1)

# Pregunta: ¿Cuál es I_res si aplico firewall?
q1 = infer.query(variables=["I_res"], evidence={"CM": "firewall"})
print("\nP(I_res | CM=firewall):")
print(q1)

# Pregunta: ¿Cuál es A_res si aplico firewall?
q1 = infer.query(variables=["A_res"], evidence={"CM": "firewall"})
print("\nP(A_res | CM=firewall):")
print(q1)

# Pregunta (opcional): ¿y si además sabemos que hay amenaza?
q2 = infer.query(variables=["C_res"], evidence={"CM": "firewall", "Threat": "yes"})
print("\nP(C_res | CM=firewall, Threat=yes):")
print(q2)

# Pregunta probabilidad de riesgo alto dado que hay amenaza
q3 = infer.query(variables=["Risk"], evidence={"Threat": "yes", "CM": "firewall"})
print("\nP(Risk | Threat=yes, CM=firewall):")
print(q3)
"""

#========================================[FUNCIONES AUXILIARES]========================================#
def get_cia_res_levels(cia_res_query):
    """
    Extrae los niveles de impacto CIA_RES (low, medium, high) desde las probabilidades inferidas.
    
    Args:
        cia_res_query: resultado de una consulta de inferencia sobre un nodo CIA_RES
    
    Returns:
        dict: diccionario con estados como claves y probabilidades como valores
    """
    probs_cia_res = cia_res_query.values
    states_names = cia_res_query.state_names[cia_res_query.variables[0]]
    
    cia_res = {}
    for state, prob in zip(states_names, probs_cia_res):
        cia_res[state] = float(prob)
    
    return cia_res


#========================================[INICIALIZACIÓN]========================================#
choice = random.choice(MITRE_TACTICS)
print(f"Construyendo red bayesiana para táctica: {choice}")
infer = bayesian_network_construction()

#--- (Ejemplos de uso comentados) ---

# Obtener distribuciones de impacto residual
c_res = infer.query(variables=["C_res"], evidence={"CM": "none"})
print("\nP(C_res):")
print(c_res)
c_res_levels = get_cia_res_levels(c_res)

i_res = infer.query(variables=["I_res"], evidence={"CM": "none"})
print("\nP(I_res):")
print(i_res)
i_res_levels = get_cia_res_levels(i_res)

a_res = infer.query(variables=["A_res"], evidence={"CM": "none"})
print("\nP(A_res):")
print(a_res)
a_res_levels = get_cia_res_levels(a_res)


