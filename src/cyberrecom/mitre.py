"""
Se consulta el dataset MITRE ATT&CK local para obtener tácticas, TTPs y mitigaciones.
También se incluyen utilidades de simulación para generar TTPs de prueba con confianza asociada.
"""

#===========================================[IMPORTS]===========================================#
from pathlib import Path
from mitreattack.stix20 import MitreAttackData
from tabulate import tabulate


#===========================================[SUPPORT_IMPORTS]===========================================#
import random
import json

#=============================[CONSTANTS]===========================================#
MITRE_ATTACK_JSON_PATH = Path(__file__).parent.parent.parent / "data" / "enterprise-attack.json"
MITRE_ATTACK_DATA = MitreAttackData(stix_filepath=str(MITRE_ATTACK_JSON_PATH))


#===========================================[MITRE FUNCTIONS]===========================================#
def get_mitre_tactics(remove_revoked_deprecated: bool = True):
    """
    Obtiene la lista de tácticas ATT&CK desde el conjunto de datos MITRE ATT&CK.

    Args:
        remove_revoked_deprecated: Indica si se excluyen tácticas revocadas u obsoletas.

    Returns:
        Lista de tácticas MITRE ATT&CK disponibles.
    """
    tactics = MITRE_ATTACK_DATA.get_tactics(remove_revoked_deprecated=remove_revoked_deprecated)
    return tactics

def get_ttp_details_from_ttp_id(ttp_id: str):
    """
    Obtiene detalles básicos de una TTP a partir de su identificador.
    Se imprime una tabla con nombre, ID, fase de kill chain y descripción resumida.

    Args:
        ttp_id: Identificador MITRE ATT&CK de la técnica.

    Returns:
        Fase de kill chain asociada a la TTP, o None si no se encuentra.
    """
    try:
        ttp = MITRE_ATTACK_DATA.get_object_by_attack_id(ttp_id, "attack-pattern")
    except ValueError:
        print(f"TTP with ID {ttp_id} not found.")
        return
        
    # Se extraen los campos principales para mostrarlos por consola
    ttp_name = ttp['name']
    ttp_description = ttp['description']
    ttp_kill_chain_phases = ttp['kill_chain_phases'][0]['phase_name']
    
    # Se prepara una tabla compacta con los detalles de la TTP
    table_data = [
        ["Nombre", ttp_name],
        ["ID", ttp_id],
        ["Fase de Kill Chain", ttp_kill_chain_phases],
         ["Descripción", ttp_description[:400] + "..."],
    ]

    print(tabulate(table_data, tablefmt="simple"))
    
    return ttp_kill_chain_phases


def get_ttp_name_from_ttp_id(ttp_id: str):
    """
    Obtiene el nombre de una TTP sin imprimir detalles por consola.

    Args:
        ttp_id: Identificador MITRE ATT&CK de la técnica.

    Returns:
        Nombre de la TTP o None si no se encuentra.
    """
    try:
        ttp = MITRE_ATTACK_DATA.get_object_by_attack_id(ttp_id, "attack-pattern")
    except ValueError:
        print(f"TTP with ID {ttp_id} not found.")
        return None

    return ttp.get("name")
   
    
def ttp_simulation():
    """
    Simula la llegada de varios TTPs con niveles de confianza aleatorios.
    Se seleccionan únicamente técnicas válidas del dataset MITRE ATT&CK local.

    Args:
        None.

    Returns:
        Diccionario con TTPs simuladas, nombre, confianza y táctica asociada.
    """
    # Se obtienen técnicas válidas y se selecciona una muestra aleatoria
    techniques = MITRE_ATTACK_DATA.get_techniques(remove_revoked_deprecated=True)
    
    n_ttps = random.randint(1, 3)  # Simular entre 1 y 3 TTPs

    if not techniques:
        print("Error: No se encontraron técnicas en MITRE ATT&CK")
        return None
    
    random_techniques = random.sample(techniques, n_ttps)
    
    
    # Se genera una confianza independiente para cada TTP seleccionada
    ttp_data = {}
    for technique in random_techniques:
        ttp_id = technique['external_references'][0]['external_id']
        confidence = random.uniform(0.3, 1.0)
        ttp_data[ttp_id] = {
            'name': technique['name'],
            'confidence': confidence,
            'tactic': get_ttp_details_from_ttp_id(ttp_id)
        }
    
    print(f"Simulación de TTPs: {ttp_data}")
    
    return ttp_data  
    t_possible_mitigations_for_ttp(ttp_id)
    

def get_possible_mitigations_for_ttp(ttp_id: str):
    """
    Devuelve las mitigaciones asociadas a una TTP.
    Se consulta el mapeo local entre técnicas y mitigaciones.

    Args:
        ttp_id: Identificador MITRE ATT&CK de la técnica.

    Returns:
        Lista de mitigaciones asociadas a la TTP.
    """
    # Se carga el mapeo local de TTPs a mitigaciones
    with open(Path(__file__).parent.parent.parent / "configs" / "ttps_to_mitigations.json", "r", encoding="utf-8") as f:
        ttps_to_mitigations = json.load(f)

    mitigations = ttps_to_mitigations.get(ttp_id, [])

    if mitigations:
        print(f"Mitigaciones para TTP {ttp_id}:")
        print(mitigations["mitigations"])
        
        return mitigations["mitigations"]
    
    else:
        print(f"No se encontraron mitigaciones para el TTP {ttp_id}.")
        raise ValueError(f"No mitigations found for TTP {ttp_id}")


def get_mitigations_for_ttp(ttp_id: str):
    """
    Alias de compatibilidad para reutilizar la llamada existente desde runner.

    Args:
        ttp_id: Identificador MITRE ATT&CK de la técnica.

    Returns:
        Lista de mitigaciones asociadas a la TTP.
    """
    return get_possible_mitigations_for_ttp(ttp_id)
    

def check_ttp_exists(ttp_id: str) -> bool:
    """
    Verifica si una TTP con el ID dado existe en MITRE ATT&CK.

    Args:
        ttp_id: Identificador MITRE ATT&CK de la técnica.

    Returns:
        True si la TTP existe; False en caso contrario.
    """
    try:
        MITRE_ATTACK_DATA.get_object_by_attack_id(ttp_id, "attack-pattern")
        return True
    except ValueError:
        return False
    
def single_ttp_simulation():
    """
    Simula la llegada de una única TTP con un nivel de confianza aleatorio.
    Se selecciona una técnica válida del dataset MITRE ATT&CK local.

    Args:
        None.

    Returns:
        Diccionario con TTP simulada, nombre, confianza y táctica asociada.
    """
    # Se obtiene una técnica válida aleatoria
    techniques = MITRE_ATTACK_DATA.get_techniques(remove_revoked_deprecated=True)

    if not techniques:
        print("Error: No se encontraron técnicas en MITRE ATT&CK")
        return None
    
    technique = random.choice(techniques)
    
    ttp_id = technique['external_references'][0]['external_id']
    confidence = random.uniform(0.3, 1.0)
    
    ttp_data = {
        'ttp_id': ttp_id,
        'name': technique['name'],
        'confidence': confidence,
        'tactic': get_ttp_details_from_ttp_id(ttp_id)
    }
    
    print(f"Simulación de TTP: {ttp_data}")
    
    return ttp_data
    
def list_ttps():
    """
    Lista todas las TTPs disponibles en MITRE ATT&CK.

    Args:
        None.

    Returns:
        Lista de tuplas con identificador y nombre de cada TTP.
    """
    techniques = MITRE_ATTACK_DATA.get_techniques(remove_revoked_deprecated=True)
    
    ttp_list = []
    for technique in techniques:
        ttp_id = technique['external_references'][0]['external_id']
        ttp_name = technique['name']
        ttp_list.append((ttp_id, ttp_name))
    
    return ttp_list      
    


#===========================================[MAIN FUNCTION]===========================================#
def main():
    """
    Ejecuta una prueba manual de consulta y simulación sobre MITRE ATT&CK.

    Args:
        None.

    Returns:
        None. Se imprimen tácticas, simulaciones y mitigaciones por consola.
    """
    
    # Se muestran tácticas disponibles y se ejecuta una simulación básica
    tactics = get_mitre_tactics()
    for tactic in tactics:
        print(f"Tactic ID: {tactic['id']}, Name: {tactic['name']}")
    
    ttp_id = "T1190"
    #get_ttp_details_from_ttp_id(ttp_id)
    ttp_sim = ttp_simulation()
   # ttp_tactic = get_ttp_details_from_ttp_id(ttp_sim['ttp_id'])
    '''
    for ttp_id in ttp_sim.keys():
        print(f"TTP ID: {ttp_id}, Confidence: {ttp_sim[ttp_id]['Confidence']}, Tactic: {ttp_sim[ttp_id]['Tactic']}")
    '''

    get_possible_mitigations_for_ttp(ttp_id)

if __name__ == "__main__":
    main()
