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
    
dependency_type_probabilities_path = Path(__file__).parent.parent.parent / "configs" / "dependency_matrix.json"
with open(dependency_type_probabilities_path, "r") as data:
    dependency_type_probabilities = json.load(data)    

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
def bayesian_network_construction(tactic="default", confidence=0.5):
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


def get_res_threat_prob(affected_edges_by_level, affected_nodes_by_level, random_threat_vectors):
    """
    Calcula P(Threat) para cada nodo afectado en cada nivel.
    P(TB) = P(TA) * P(EA→B | TA)
    """
    # Diccionario con clave nombre del nodo y valor datos de threat
    nodes_threat_prob = {}
    
    for ttp_id, threat_vector in random_threat_vectors.items():
        confidence = threat_vector['confidence']
        ttp_tactic = threat_vector['tactic']
        
        # Obtener datos para este TTP
        try:
            nodes_data = affected_nodes_by_level.get(ttp_id, {})
            edges_data = affected_edges_by_level.get(ttp_id, {})
        except KeyError:
            print(f"Error: No se encontraron datos para TTP {ttp_id} en nodos o aristas afectados.")
            continue
        
        # Procesar edges: agregar P(trans) y eliminar weight
        for level, edge_list in edges_data.items():
            for edge_info in edge_list:
                dependency_type = edge_info['dependency_type']
                edge_info[f'P(trans_{ttp_tactic}|Threat = yes)'] = dependency_type_probabilities[ttp_tactic][dependency_type]
                edge_info.pop('weight', None)
        
        # NIVEL 0: P(Threat) = confidence
        for asset in nodes_data.get(0, []):
            nodes_threat_prob[asset] = {
                'P(Threat)': confidence,
                'level': 0,
                'ttp': ttp_id
            }
            
            
        
        # NIVELES > 0: P(Threat asset_from {hijo}) = P(Threat asset_to {padre}) * P(dependency_type|threat=yes)
        for level in range(0, len(nodes_data)):
            for asset_from in nodes_data.get(level, []):
                # Buscar el edge donde este nodo es el dependiente (from) para ese nivel
                for edge in edges_data.get(level, []):
                    if edge['from'] == asset_from:
                        asset_to = edge['to']  # El nodo del que depende
                        p_trans_key = f'P(trans_{ttp_tactic}|Threat = yes)'
                        p_trans = edge.get(p_trans_key, 0)
                        
                        # P(Threat) del nodo del que depende
                        if asset_to in nodes_threat_prob:
                            p_threat_parent = nodes_threat_prob[asset_to]['P(Threat)']
                            nodes_threat_prob[asset_from] = {
                                'P(Threat)': p_threat_parent * p_trans,
                                'level': level,
                                'ttp': ttp_id,
                                'depends_on': asset_to
                            }
                            print(f"Calculando P(Threat) para {asset_from} (nivel {level}): P(Threat)({asset_to})={p_threat_parent} * P(trans|Threat = yes)={p_trans} = {nodes_threat_prob[asset_from]['P(Threat)']}") 
                        break
                
    
    return nodes_threat_prob


#========================================[INICIALIZACIÓN]========================================#
def main():
    choice = random.choice(MITRE_TACTICS)
    print(f"Construyendo red bayesiana para táctica: {choice}")
    infer = bayesian_network_construction(choice, confidence)

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


