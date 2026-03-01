#==============================[IMPORTS]===========================================#
import datetime
from cyberrecom.main import DB_PATH, EXCEL_PATH




#===============================[JSON FUNCTIONS]===========================================#

def initialize_simulation_data(threat_vector: dict) -> dict:
    """Inicializa la estructura de datos para almacenar resultados de simulación"""
    
    return {
        "metadata": {
            "timestamp": datetime.now().isoformat(),
            "version": "1.0.0",
            "threat_ttp_id": threat_vector['ttp_id'],
            "threat_confidence": float(threat_vector['confidence']),
            "initial_asset": threat_vector['asset'],
            "tactic": threat_vector['tactic'],
            "db_path": str(DB_PATH),
            "excel_source": str(EXCEL_PATH)
        },
        "threat_vector": threat_vector,
        "affected_nodes": {},
        "affected_edges": {},
        "levels_analysis": {}
    }