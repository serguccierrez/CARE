import red_bayes
import json
from pathlib import Path

#========================================[LECTURA DE CONFIGURACIÓN]========================================#
def read_constants():
    """
    Lee las constantes de niveles de impacto desde el archivo de configuración.
    
    Returns:
        dict: diccionario con todas las constantes del proyecto
    """
    with open(Path(__file__).parent.parent.parent / "configs" / "constants.json", "r") as f:
        constants = json.load(f)
    return constants

def read_cms():
    """
    Lee los nombres de las contramedidas disponibles desde el archivo CPDs.
    
    Returns:
        list: lista de estados/nombres de contramedidas
    """
    with open(Path(__file__).parent.parent.parent / "configs" / "bn_CPDs.json", "r") as f:
        cms = json.load(f)["CM"]["states"]
    return cms


#========================================[CONSTANTES]========================================#
IMPACT_LEVELS = read_constants()["impact_levels"]
print(f"Constantes de impacto: {IMPACT_LEVELS}")

COUNTERMEASURES = read_cms()
print(f"Contramedidas disponibles: {COUNTERMEASURES}")

#========================================[CÁLCULO DE IMPACTO NUMÉRICO]========================================#
def calculate_numeric_impact():
    """
    Calcula un impacto numérico ponderado para cada contramedida a partir de las probabilidades
    de los resultados residuales en las dimensiones CIA (Confidentiality, Integrity, Availability).
    
    El impacto se calcula como: suma de (probabilidad x nivel_impacto) para cada estado.
    
    Returns:
        dict: diccionario con estructura {contramedida: {"C_res": valor, "I_res": valor, "A_res": valor}}
    """
    #=================={Inicialización del modelo y diccionario de impactos}========================#
    infer = red_bayes.bayesian_network_construction()
    numeric_impacts = {}

    #=================={Evaluación de cada contramedida}========================#
    for cm in COUNTERMEASURES:
        print(f"\nEvaluando impacto para la contramedida: {cm}")
        
        #--- Consultamos los valores de C_res, I_res y A_res condicionados a la contramedida ---
        c_res = infer.query(variables=["C_res"], evidence={"CM": cm})
        c_res_levels = red_bayes.get_cia_res_levels(c_res)

        i_res = infer.query(variables=["I_res"], evidence={"CM": cm})
        i_res_levels = red_bayes.get_cia_res_levels(i_res)

        a_res = infer.query(variables=["A_res"], evidence={"CM": cm})
        a_res_levels = red_bayes.get_cia_res_levels(a_res)
        
        #--- Calculamos impactos ponderando cada nivel por su probabilidad ---
        c_res_impact = sum(prob * int(IMPACT_LEVELS[level]) for level, prob in c_res_levels.items())
        numeric_impacts[cm] = {"C_res": c_res_impact}
        print(f"Impacto numérico de C_res: {c_res_impact}")
        
        i_res_impact = sum(prob * int(IMPACT_LEVELS[level]) for level, prob in i_res_levels.items())
        numeric_impacts[cm]["I_res"] = i_res_impact
        print(f"Impacto numérico de I_res: {i_res_impact}")
        
        a_res_impact = sum(prob * int(IMPACT_LEVELS[level]) for level, prob in a_res_levels.items())
        numeric_impacts[cm]["A_res"] = a_res_impact
        print(f"Impacto numérico de A_res: {a_res_impact}")
        
    return numeric_impacts


#========================================[EJECUCIÓN]========================================#
impacts = calculate_numeric_impact()
print("\nImpactos numéricos calculados para cada contramedida:")
print(impacts)