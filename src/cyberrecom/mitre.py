#===========================================[IMPORTS]===========================================#
from pathlib import Path
from mitreattack.stix20 import MitreAttackData
from tabulate import tabulate


#======TEST=====
import random


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
    
    if not techniques:
        print("Error: No se encontraron técnicas en MITRE ATT&CK")
        return None
    
    # Seleccionar una técnica aleatoria
    random_technique = random.choice(techniques)
    ttp_id = random_technique['external_references'][0]['external_id']  # Ej: T1190
    confidence = random.random()
    
    print(f"Simulación de TTP: {ttp_id}, Confidence: {confidence:.2f}")
    
    return dict(ttp_id=ttp_id, confidence=confidence)
    
      
    
    


#===========================================[MAIN FUNCTION]===========================================#
def main():
    
    tactics = get_mitre_tactics()
    for tactic in tactics:
        print(f"Tactic ID: {tactic['id']}, Name: {tactic['name']}")
    
    #ttp_id = "T1190"
    #get_ttp_details_from_ttp_id(ttp_id)
    ttp_sim = ttp_simulation()
    ttp_tactic = get_ttp_details_from_ttp_id(ttp_sim['ttp_id'])
    print(f"TTP {ttp_sim['ttp_id']} belongs to tactic: {ttp_tactic}")
    

if __name__ == "__main__":
    main()