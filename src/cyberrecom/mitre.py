#===========================================[IMPORTS]===========================================#
from pathlib import Path
from mitreattack.stix20 import MitreAttackData
from tabulate import tabulate


#======TEST=====
import random
import json

#=============================[CONSTANTS]===========================================#
MITRE_ATTACK_JSON_PATH = Path(__file__).parent.parent.parent / "data" / "enterprise-attack.json"
MITRE_ATTACK_DATA = MitreAttackData(stix_filepath=str(MITRE_ATTACK_JSON_PATH))


#===========================================[MITRE FUNCTIONS]===========================================#
def get_mitre_tactics(remove_revoked_deprecated: bool = True):
    """
    Obtiene la lista de tácticas ATT&CK desde el conjunto de datos MITRE ATT&CK.
    """
    tactics = MITRE_ATTACK_DATA.get_tactics(remove_revoked_deprecated=remove_revoked_deprecated)
    return tactics

def get_ttp_details_from_ttp_id(ttp_id: str):
    """
    Obtiene la táctica asociada a una TTP específica.
    """
    try:
        ttp = MITRE_ATTACK_DATA.get_object_by_attack_id(ttp_id, "attack-pattern")
        #MITRE_ATTACK_DATA.print_stix_object(ttp, pretty=True)
    except ValueError:
        print(f"TTP with ID {ttp_id} not found.")
        return
        
    #Details
    ttp_name = ttp['name']
    ttp_description = ttp['description']
    ttp_kill_chain_phases = ttp['kill_chain_phases'][0]['phase_name']
    
    # Crear tabla
    table_data = [
        ["Nombre", ttp_name],
        ["ID", ttp_id],
        ["Fase de Kill Chain", ttp_kill_chain_phases],
         ["Descripción", ttp_description[:400] + "..."],
    ]

    # Imprimir tabla
    print(tabulate(table_data, tablefmt="simple"))
    
    return ttp_kill_chain_phases
   
    
def ttp_simulation():
    '''
    Simula la llegada de un TTP sobre un activo con un cierto nivel de confidence.
    Solo selecciona TTPs que existen realmente en MITRE ATT&CK.
    '''
    # Obtener todas las técnicas válidas
    techniques = MITRE_ATTACK_DATA.get_techniques(remove_revoked_deprecated=True)
    
    n_ttps = random.randint(1, 3)  # Simular entre 1 y 3 TTPs

    if not techniques:
        print("Error: No se encontraron técnicas en MITRE ATT&CK")
        return None
    
    # Seleccionar una técnica aleatoria
    random_techniques = random.sample(techniques, n_ttps)
    
    
    #Si tenemos más de un TTP, debemos tener más parámetros de confidence, uno para cada TTP
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
    

def get_possible_mitigations_for_ttp(ttp_id: str):
    '''
    Dado un TTP, devuelve las posibles mitigaciones asociadas a ese TTP.
    '''
    # Cargamos el json ttps_to_mitigations.json
    with open(Path(__file__).parent.parent.parent / "configs" / "ttps_to_mitigations.json", "r") as f:
        ttps_to_mitigations = json.load(f)

    mitigations = ttps_to_mitigations.get(ttp_id, [])

    if mitigations:
        print(f"Mitigaciones para TTP {ttp_id}:")
        print(mitigations["mitigations"])

        mitigations.append()
        
        return mitigations["mitigations"]
    
    else:
        print(f"No se encontraron mitigaciones para el TTP {ttp_id}.")
        raise ValueError(f"No mitigations found for TTP {ttp_id}")
    

def check_ttp_exists(ttp_id: str) -> bool:
    '''
    Verifica si una TTP con el ID dado existe en MITRE ATT&CK.
    '''
    try:
        MITRE_ATTACK_DATA.get_object_by_attack_id(ttp_id, "attack-pattern")
        return True
    except ValueError:
        return False
    
def single_ttp_simulation():
    '''
    Simula la llegada de un único TTP sobre un activo con un cierto nivel de confidence.
    Solo selecciona TTPs que existen realmente en MITRE ATT&CK.
    '''
    # Obtener todas las técnicas válidas
    techniques = MITRE_ATTACK_DATA.get_techniques(remove_revoked_deprecated=True)

    if not techniques:
        print("Error: No se encontraron técnicas en MITRE ATT&CK")
        return None
    
    # Seleccionar una técnica aleatoria
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
    '''
    Lista todas las TTPs disponibles en MITRE ATT&CK.
    '''
    techniques = MITRE_ATTACK_DATA.get_techniques(remove_revoked_deprecated=True)
    
    ttp_list = []
    for technique in techniques:
        ttp_id = technique['external_references'][0]['external_id']
        ttp_name = technique['name']
        ttp_list.append((ttp_id, ttp_name))
    
    return ttp_list      
    


#===========================================[MAIN FUNCTION]===========================================#
def main():
    
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