#=============================================[IMPORTS]=============================================
import json
from pathlib import Path
import pulp


#===========================================[CARGA DE DATOS NECESARIOS]===========================================

def load_report_data():
    report_path = Path(__file__).parent.parent / "reporting" / "report.json"
    
    with open(report_path, "r", encoding="utf-8") as f:
        return json.load(f)
    
def load_countermeasures_config():
    config_path = Path(__file__).parent.parent.parent / "configs" / "countermeasures.json"

    
    with open(config_path, "r", encoding="utf-8") as f:
        return json.load(f)


#===========================================[OPTIMIZATION PROBLEM PREPARATION]===========================================
def extract_asset_scenarios_info(report_data, cm_config):
    """
    Extrae información de escenarios por activo y enriquece con propiedades de contramedidas.
    
    Fusiona la extracción de propiedades de contramedidas con el enriquecimiento de escenarios
    en una sola pasada para eficiencia.
    
    Args:
        report_data: Datos del reporte con escenarios de activos
        cm_config: Configuración de contramedidas con información de coste y tiempo
    
    Returns:
        Diccionario con escenarios de cada activo enriquecidos con coste y tiempo
    """
    
    # Extraer propiedades de contramedidas directamente desde el catálogo
    cm_properties = {}
    for cm_id, cm_data in cm_config.get("countermeasures", {}).items():
        cm_properties[cm_id] = {
            "name": cm_data["name"],
            "cost": cm_data["cost"],
            "time": cm_data["time_to_deploy_hours"]
        }
    
    assets_scenarios_data = {}
    
    for block in report_data.get("nodes_analysis", []):
        for asset_name, asset_info in block.items():
            
            asset_scenarios = asset_info.get("asset_scenarios", {})
            
            if not asset_scenarios:
                continue
            
            # Variable auxiliar para cargar los escenarios y añadir datos adicionales
            scenarios = {}
    
            for scenario_key, scenario_data in asset_scenarios.items():
                
                # Extraemos el nombre de la contramedida aplicada para cada escenario
                cm_name = scenario_data["countermeasure_applied"]
                
                # Comprobamos que la cm esté modelada en el catálogo y extraemos sus propiedades
                if cm_name not in cm_properties:
                        raise ValueError(f"[ERROR] Contramedida '{cm_name}' no encontrada en el catálogo")
                cost = cm_properties[cm_name]["cost"]
                time_hours = cm_properties[cm_name]["time"]
                
                # Creamos un nuevo diccionario con la información relevante para cada escenario
                scenarios[scenario_key] = {
                    "countermeasure": cm_name,
                    "risk_total": scenario_data["total_asset_risk"],
                    "risk_C": scenario_data["asset_risk_C"],
                    "risk_I": scenario_data["asset_risk_I"],
                    "risk_A": scenario_data["asset_risk_A"],
                    "cost": cost,
                    "time_hours": time_hours
                }
            
            assets_scenarios_data[asset_name] = {
                "criticality": asset_info["node_data"]["criticality"],
                "scenarios": scenarios
            }
    
    return assets_scenarios_data


#===========================================[DECISION VARIABLES CREATION]===========================================
def create_decision_variables(assets_scenarios_data):
    """
    Crea variables de decisión binarias para cada escenario de cada activo.
    
    Args:
        assets_scenarios_data: Diccionario con escenarios de cada activo enriquecidos con coste y tiempo
    
    Returns:
        Diccionario con variables de decisión para cada escenario de cada activo
    """
    
    decision_vars = {}
    
    for asset_name, scenarios_data in assets_scenarios_data.items():
        
        decision_vars[asset_name] = {}
        
        for scenario_name in scenarios_data["scenarios"].keys():
            
            var_name = f"x_{asset_name}_{scenario_name}"
            
            # Creamos una variable de decisión binaria para cada escenario de cada activo con la fomra x['asset_name']['scenario_name']
            # Serán variabales binarias que indicarán si se selecciona o no ese escenario para ese activo
            # Ejemplo: x['asset_001']['scenario_1'] = 1 si se selecciona el escenario 1 para el activo 001, 0 en caso contrario
            decision_vars[asset_name][scenario_name] = pulp.LpVariable(var_name, cat="Binary")
    
    return decision_vars

#===============================================[OBJECTIVE FUNCTION]=============================================
def define_objective_function(decision_vars, assets_scenarios_data, model):
    """
    Define la función objetivo para minimizar el riesgo total ponderado por criticidad.
    
    Args:
        model: Instancia del modelo de optimización de PuLP
        decision_vars: Diccionario con variables de decisión para cada escenario de cada activo
        assets_scenarios_data: Diccionario con escenarios de cada activo enriquecidos con coste y tiempo
    
    Returns:
        None (la función objetivo se agrega directamente al modelo)
    """
    

    
    objective = 0
    
    for asset_name, asset_data in assets_scenarios_data.items():
        
        criticality = asset_data.get("criticality", 1.0 )
        
        for scenario_name, scenario_info in asset_data["scenarios"].items():
            
            risk_value = scenario_info["risk_total"]
            
            
            objective += (criticality * risk_value) * decision_vars[asset_name][scenario_name]

            
        
        
    model += objective, "Minimize_Risk_Weighted_by_Criticality"


#===============================================[CONSTRAINTS]=============================================
def unique_cm_per_asset_constraint(decision_vars, model):

    """
    Agrega la restricción de que solo se puede seleccionar un escenario (contramedida) por activo.
    
    Args:
        model: Instancia del modelo de optimización de PuLP
        decision_vars: Diccionario con variables de decisión para cada escenario de cada activo
    
    Returns:
        None (las restricciones se agregan directamente al modelo)
    """
    
    for asset_name, asset_data in decision_vars.items():
        
        constraint = pulp.lpSum([asset_data[scenario] for scenario in asset_data]) == 1
        
        model += constraint, f"Unique_CM_for_{asset_name}"
        
def budget_constraint(decision_vars, assets_scenarios_data, budget, model):
    """
    Agrega la restricción de presupuesto total para las contramedidas seleccionadas.
    
    Args:
        model: Instancia del modelo de optimización de PuLP
        decision_vars: Diccionario con variables de decisión para cada escenario de cada activo
        assets_scenarios_data: Diccionario con escenarios de cada activo enriquecidos con coste y tiempo
        budget: Presupuesto total disponible para las contramedidas
    
    Returns:
        None (la restricción se agrega directamente al modelo)
    """
    
    total_cost = 0
    
    for asset_name, asset_info in assets_scenarios_data.items():
        
        for scenario_name, scenario_data in asset_info["scenarios"].items():
            
            cost = scenario_data["cost"]
            total_cost += cost * decision_vars[asset_name][scenario_name]
    
    model += total_cost <= budget, "Budget_Constraint"
    
    
    
#==============================================[OPTIMIZATION PROBLEM SOLVING]=============================================
def solve_optimization_problem(decision_vars, assets_scenarios_data ,model, budget, report_data = None):
    """
    Resuelve el problema de optimización utilizando el solver de PuLP.
    
    Args:
        model: Instancia del modelo de optimización de PuLP con función objetivo y restricciones definidas
        budget: Presupuesto total disponible para las contramedidas
        report_data: Datos del informe para almacenar información sobre la solución
    Returns:
        status: Estado de la solución (Optimal, Infeasible, etc.)
        solution: Diccionario con la solución óptima encontrada para las variables de decisión
    """
    
    if report_data is None:
        report_data = load_report_data()
    
    model.solve(pulp.PULP_CBC_CMD(msg=1))
    
    status = pulp.LpStatus[model.status]
    print(f"Status: {status}")
    
    if status != "Optimal":
        print(f"[WARN] Solución no óptima: {status}")
    
    
    # Obtenemos la suma de criticidades para su posterior normalización del riesgo total
    total_criticality = sum(
        asset_info.get("criticality", 1.0) 
        for asset_info in assets_scenarios_data.values()
    )
    
    
    
    optimal_risk_weighted = pulp.value(model.objective) # Valor objetivo (suma ponderada - numerador)
    optimal_risk_normalized = optimal_risk_weighted / total_criticality # Riesgo total normalizado (dividido por la suma de criticidades - denominador)
    
    print(f"Riesgo global mínimo (ponderado): {optimal_risk_weighted:.4f}")
    print(f"Riesgo global mínimo (normalizado): {optimal_risk_normalized:.4f}")
    print(f"Suma de criticidades: {total_criticality:.4f}")
    
    
    # Creamos un diccionario con la solución óptima encontrada para cada activo y escenario
    solution = {
        "status": status,
        "baseline_risk": report_data["global_system_risk"]["overall_risk"],
        "optimal_risk_weighted": optimal_risk_weighted,
        "optimal_risk_normalized": optimal_risk_normalized,
        "risk_reduction": report_data["global_system_risk"]["overall_risk"] - optimal_risk_normalized,
        "total_criticality": total_criticality,
        "assets_decisions": {},
        "budget": budget,
        "total_cost": 0.0,
        "total_cost_used_percent": 0.0
    }
    
    # Para cada activo, determinar qué escenario fue seleccionado
    for asset_name, scenarios in decision_vars.items():
        for scenario_name, scenario_var in scenarios.items():
            if scenario_var.varValue == 1:  # Si este escenario ha sido seleccionado (valor = 1)
                scenario_data = assets_scenarios_data[asset_name]["scenarios"][scenario_name]
                criticality = assets_scenarios_data[asset_name]["criticality"]
                
                solution["assets_decisions"][asset_name] = {
                    "scenario": scenario_name,
                    "countermeasure": scenario_data["countermeasure"],
                    "risk_total": scenario_data["risk_total"],
                    "risk_C": scenario_data["risk_C"],
                    "risk_I": scenario_data["risk_I"],
                    "risk_A": scenario_data["risk_A"],
                    "criticality": criticality,
                    "weighted_risk": scenario_data["risk_total"] * criticality,
                    "cost": scenario_data["cost"],
                    "time_hours": scenario_data["time_hours"]
                }
                
                solution["total_cost"] += scenario_data["cost"]
    solution["total_cost_used_percent"] = str((solution["total_cost"] / budget) * 100 if budget != 0 else 0) + "%"
   
                
    print("La solución óptima encontrada es:")
    print(json.dumps(solution, indent=4))
                
    return solution


#======================================================[LP INTEGRATION]======================================================
def build_optimization_problem(assets_scenarios_data, decision_vars, budget = 50000):
    """
    Ejecuta el proceso completo de optimización: creación de variables, definición de función objetivo, adición de restricciones y resolución del problema.
    
    Args:
        assets_scenarios_data: Diccionario con escenarios de cada activo enriquecidos con coste y tiempo
        decision_vars: Variables de decisión para cada activo y escenario
        budget: Presupuesto total disponible para las contramedidas
        
    Returns:
    """
    # Primero creamos el problema de optimización
    model = pulp.LpProblem("Minimize_Global_Risk", pulp.LpMinimize)
    
    # Definimos la función objetivo
    define_objective_function( decision_vars, assets_scenarios_data, model)
    
    # Añadimos las restricciones
    unique_cm_per_asset_constraint(decision_vars, model)
    budget_constraint(decision_vars, assets_scenarios_data, budget, model)
    
    return model

def setup_optimization_problem( report_data, budget = 50000):
    
    if report_data is None:
        report_data = load_report_data()
   
    cm_config = load_countermeasures_config()
    
    assets_scenarios_data = extract_asset_scenarios_info(report_data, cm_config)
    
    decision_vars = create_decision_variables(assets_scenarios_data)
    
    model = build_optimization_problem(assets_scenarios_data, decision_vars, budget)
    
    return assets_scenarios_data, decision_vars, model


