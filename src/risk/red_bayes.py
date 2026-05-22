"""
Se construye una red bayesiana discreta para estimar impactos residuales CIA.
También se calculan probabilidades de amenaza propagadas por dependencias entre activos.
"""

#========================================[IMPORTS]========================================#
from pathlib import Path
import random
from pgmpy.models import DiscreteBayesianNetwork
from pgmpy.factors.discrete import TabularCPD
from pgmpy.inference import VariableElimination

import json

#========================================[CONFIGURACIÓN]========================================#
confidence = 0.8

def read_bn_cpds():
    """
    Lee las CPDs de la red bayesiana desde el archivo de configuración.

    Args:
        None.

    Returns:
        Diccionario con estados y distribuciones de probabilidad del modelo.
    """
    bn_cpds_path = Path(__file__).parent.parent.parent / "configs" / "bn_CPDs.json"
    with open(bn_cpds_path, "r") as data:
        cpd_data = json.load(data)
    return cpd_data

    
# Se carga la matriz de propagación por táctica y tipo de dependencia
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
    Se modelan amenaza, riesgo, contramedida e impactos residuales en confidencialidad, integridad y disponibilidad.
    
    La red bayesiana representa las relaciones probabilísticas entre:
    - Threat: probabilidad de que haya una amenaza
    - Risk: riesgo resultante de la amenaza
    - CM: contramedida aplicada
    - C_res, I_res, A_res: impactos residuales en las tres dimensiones CIA
    
    Args:
        tactic: Nombre de la táctica para seleccionar las CPDs específicas de riesgo dado amenaza.
        confidence: Probabilidad inicial de amenaza usada en el nodo Threat.
    
    Returns:
        Motor de inferencia VariableElimination para consultar la red.
    """
    # Se cargan las CPDs desde configuración
    cpd_data = read_bn_cpds()
    
    
    # Se define la estructura acíclica de la red bayesiana
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
    # Se definen las distribuciones de probabilidad del modelo
    
    # Threat: probabilidad de amenaza
    cpd_threat = TabularCPD(
        variable="Threat",
        variable_card=len(cpd_data["Threat"]["states"]),
        values=[[1 - confidence], [confidence]],
        state_names={"Threat": cpd_data["Threat"]["states"]}
    )

    # CM: distribución de contramedidas
    cpd_cm = TabularCPD(
        variable="CM",
        variable_card=len(cpd_data["CM"]["states"]),
        values=[[p] for p in cpd_data["CM"]["values"]],
        state_names={"CM": cpd_data["CM"]["states"]}
    )

    # Risk: probabilidad de riesgo dado Threat
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

    # C_res: impacto residual en confidencialidad dado Risk y CM
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

    # I_res: impacto residual en integridad dado Risk y CM
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

    # A_res: impacto residual en disponibilidad dado Risk y CM
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

    # Se agregan las CPDs, se valida el modelo y se crea el motor de inferencia
    model.add_cpds(cpd_threat, cpd_cm, cpd_risk, cpd_c_res, cpd_i_res, cpd_a_res)

    assert model.check_model(), "Error: El modelo de red bayesiana no es correcto. Revisa las CPDs y la estructura del grafo."

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
        cia_res_query: Resultado de una consulta de inferencia sobre un nodo CIA_RES.
    
    Returns:
        Diccionario con estados como claves y probabilidades como valores.
    """
    probs_cia_res = cia_res_query.values
    states_names = cia_res_query.state_names[cia_res_query.variables[0]]
    
    cia_res = {}
    for state, prob in zip(states_names, probs_cia_res):
        cia_res[state] = float(prob)
    
    return cia_res


def get_res_threat_prob(affected_edges_by_level, affected_nodes_by_level, random_threat_vectors, grafo):
    """
    Calcula P(Threat) para cada nodo afectado en cada nivel.
    Se propaga la probabilidad inicial usando la probabilidad de transición de cada dependencia.

    Args:
        affected_edges_by_level: Aristas afectadas agrupadas por TTP y nivel.
        affected_nodes_by_level: Nodos afectados agrupados por TTP y nivel.
        random_threat_vectors: Vectores de amenaza con confianza y táctica asociada.
        grafo: Grafo NetworkX con los datos de los activos.

    Returns:
        Diccionario con probabilidades de amenaza por activo y TTP.
    """
    # Se acumulan probabilidades de amenaza por nodo afectado
    nodes_threat_prob = {}
    
    for ttp_id, threat_vector in random_threat_vectors.items():
        confidence = threat_vector['confidence']
        ttp_tactic = threat_vector['tactic']
        
        # Se obtienen nodos y aristas afectados para el TTP actual
        try:
            nodes_data = affected_nodes_by_level.get(ttp_id, {})
            edges_data = affected_edges_by_level.get(ttp_id, {})
        except KeyError:
            print(f"Error: No se encontraron datos para TTP {ttp_id} en nodos o aristas afectados.")
            continue
        
        # Se añade probabilidad de transición a cada arista afectada
        for level, edge_list in edges_data.items():
            for edge_info in edge_list:
                dependency_type = edge_info['dependency_type']
                edge_info[f'P(trans_{ttp_tactic}|Threat = yes)'] = dependency_type_probabilities[ttp_tactic][dependency_type]
                edge_info.pop('weight', None)
                
        
        # Nivel 0: la probabilidad de amenaza coincide con la confianza del vector
        for asset in nodes_data.get(0, []):
            if asset not in nodes_threat_prob:
                
                nodes_threat_prob[asset] = {
                    'threats_by_ttp': {ttp_id: {'P(Threat)': confidence} },
                    'level': 0,
                    'root': True
                }

                nodes_threat_prob[asset]['node_data'] = grafo.nodes[asset]
                
            else:
                
                nodes_threat_prob[asset]['threats_by_ttp'][ttp_id] = {
                'P(Threat)': confidence
                }
                
        
        # Niveles superiores: se propaga amenaza desde el activo del que depende
        for level in range(1, len(nodes_data)):
            for asset_from in nodes_data.get(level, []):
                for edge in edges_data.get(level, []):
                    if edge['from'] == asset_from:
                        asset_to = edge['to']
                        p_trans_key = f'P(trans_{ttp_tactic}|Threat = yes)'
                        p_trans = edge.get(p_trans_key, 0)
                        
                        p_threat_parent = nodes_threat_prob[asset_to]['threats_by_ttp'][ttp_id]['P(Threat)']
                            
                            
                        
                        if asset_from not in nodes_threat_prob:
                            nodes_threat_prob[asset_from] = {
                                'threats_by_ttp': {ttp_id: {
                                    'P(Threat)': p_threat_parent * p_trans,
                                    'level': level,
                                    'depends_on': asset_to
                                }}

                            }

                            nodes_threat_prob[asset_from]['node_data'] = grafo.nodes[asset_from]
                        
                        else:
                            nodes_threat_prob[asset_from]['threats_by_ttp'][ttp_id] = {
                            'P(Threat)': p_threat_parent * p_trans,
                            'level': level,
                            'depends_on': asset_to
                            }

                            
    #nodes_threat_prob = add_noisy_or_prob(nodes_threat_prob)
                            
    return nodes_threat_prob

'''
def add_noisy_or_prob(nodes_threat_prob):
    """
    Añade a cada nodo la probabilidad combinada
    P(Threat_combined_noisy_or) a partir de las probabilidades
    individuales P(Threat) de cada TTP.

    Si solo hay un TTP, el Noisy OR será esa misma probabilidad.
    """

    for asset, asset_data in nodes_threat_prob.items():
        threats_by_ttp = asset_data.get('threats_by_ttp', {})

        product = 1.0

        for ttp_id, ttp_data in threats_by_ttp.items():
            p = ttp_data.get('P(Threat)', 0.0)
            product *= (1 - p)

        asset_data['Total_Threat_Probability'] = 1 - product

    return nodes_threat_prob
'''

#========================================[INICIALIZACIÓN]========================================#
def main():
    """
    Ejecuta una prueba manual de construcción e inferencia de la red bayesiana.
    Se consulta el impacto residual para C, I y A sin aplicar contramedidas.

    Args:
        None.

    Returns:
        None. Se imprimen por consola las distribuciones consultadas.
    """
    choice = random.choice(MITRE_TACTICS)
    print(f"Construyendo red bayesiana para táctica: {choice}")
    infer = bayesian_network_construction(choice, confidence)

    # Se obtienen distribuciones de impacto residual para cada dimensión CIA
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


