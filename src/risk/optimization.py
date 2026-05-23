"""
Se preparan y resuelven problemas de optimización de contramedidas con PuLP.
Se minimiza el riesgo de los activos bajo restricciones de presupuesto y tiempo.
"""

#=============================================[IMPORTS]=============================================
import json
from pathlib import Path
import pulp


#===========================================[CARGA DE DATOS NECESARIOS]===========================================

def load_report_data():
    """
    Carga el reporte JSON generado por el análisis de riesgo.

    Args:
        None.

    Returns:
        Diccionario con los datos del reporte.
    """
    report_path = Path(__file__).parent.parent / "reporting" / "report.json"
    
    with open(report_path, "r", encoding="utf-8") as f:
        return json.load(f)
    
def load_countermeasures_config():
    """
    Carga el catálogo de contramedidas desde configuración.

    Args:
        None.

    Returns:
        Diccionario con las contramedidas, costes y tiempos de despliegue.
    """
    config_path = Path(__file__).parent.parent.parent / "configs" / "countermeasures.json"

    
    with open(config_path, "r", encoding="utf-8") as f:
        return json.load(f)


#===========================================[OPTIMIZATION PROBLEM PREPARATION]===========================================
def extract_asset_scenarios_info(report_data, cm_config):
    """
    Extrae información de escenarios por activo y enriquece con propiedades de contramedidas.
    Se combinan riesgos del reporte con coste y tiempo definidos en el catálogo.
    
    Args:
        report_data: Datos del reporte con escenarios de activos.
        cm_config: Configuración de contramedidas con coste y tiempo.
    
    Returns:
        Diccionario con escenarios de cada activo enriquecidos con coste y tiempo.
    """
    
    # Se indexan propiedades de contramedidas para enriquecer los escenarios
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
            
            scenarios = {}
    
            for scenario_key, scenario_data in asset_scenarios.items():
                
                # Se valida que la contramedida exista en el catálogo antes de usar sus propiedades
                cm_name = scenario_data["countermeasure_applied"]
                
                if cm_name not in cm_properties:
                        raise ValueError(f"[ERROR] Contramedida '{cm_name}' no encontrada en el catálogo")
                cost = cm_properties[cm_name]["cost"]
                time_hours = cm_properties[cm_name]["time"]
                
                scenarios[scenario_key] = {
                    "countermeasure": cm_name,
                    "risk_total": scenario_data["total_asset_risk"],
                    "asset_risk_C": scenario_data["asset_risk_C"],
                    "asset_risk_I": scenario_data["asset_risk_I"],
                    "asset_risk_A": scenario_data["asset_risk_A"],
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
        assets_scenarios_data: Diccionario con escenarios de cada activo enriquecidos.
    
    Returns:
        Diccionario con variables binarias por activo y escenario.
    """
    
    decision_vars = {}
    
    for asset_name, scenarios_data in assets_scenarios_data.items():
        
        decision_vars[asset_name] = {}
        
        for scenario_name in scenarios_data["scenarios"].keys():
            
            var_name = f"x_{asset_name}_{scenario_name}"
            
            # Se crea una variable binaria que indica si se selecciona ese escenario para el activo
            decision_vars[asset_name][scenario_name] = pulp.LpVariable(var_name, cat="Binary")
    
    return decision_vars

#===============================================[OBJECTIVE_FUNCTIONS]=============================================
def define_global_objective_function(decision_vars, assets_scenarios_data, model):
    """
    Define la función objetivo para minimizar el riesgo total ponderado por criticidad.
    
    Args:
        decision_vars: Diccionario con variables de decisión por activo y escenario.
        assets_scenarios_data: Diccionario con escenarios enriquecidos por activo.
        model: Instancia del modelo de optimización de PuLP.
    
    Returns:
        None. La función objetivo se agrega directamente al modelo.
    """
    

    
    objective = 0
    
    for asset_name, asset_data in assets_scenarios_data.items():
        
        criticality = asset_data.get("criticality", 1.0 )
        
        for scenario_name, scenario_info in asset_data["scenarios"].items():
            
            risk_value = scenario_info["risk_total"]
            
            
            objective += (criticality * risk_value) * decision_vars[asset_name][scenario_name]

        
    model += objective, "Minimize_Risk_Weighted_by_Criticality"
    
    
    
def define_confidentiality_objective_function(decision_vars, assets_scenarios_data, model):
    """
    Define la función objetivo para minimizar riesgo de confidencialidad ponderado.

    Args:
        decision_vars: Diccionario con variables de decisión por activo y escenario.
        assets_scenarios_data: Diccionario con escenarios enriquecidos por activo.
        model: Instancia del modelo de optimización de PuLP.

    Returns:
        None. La función objetivo se agrega directamente al modelo.
    """
    
    
    objective = 0
    
    for asset_name, asset_data in assets_scenarios_data.items():
        
        criticality = asset_data.get("criticality", 1.0 )
        
        for scenario_name, scenario_info in asset_data["scenarios"].items():
            
            risk_value = scenario_info["asset_risk_C"]
            
            
            objective += (criticality * risk_value) * decision_vars[asset_name][scenario_name]

            
        
        
    model += objective, "Minimize_Confidentiality_Risk_Weighted_by_Criticality"
    
    
def define_integrity_objective_function(decision_vars, assets_scenarios_data, model):
    """
    Define la función objetivo para minimizar riesgo de integridad ponderado.

    Args:
        decision_vars: Diccionario con variables de decisión por activo y escenario.
        assets_scenarios_data: Diccionario con escenarios enriquecidos por activo.
        model: Instancia del modelo de optimización de PuLP.

    Returns:
        None. La función objetivo se agrega directamente al modelo.
    """
    
    
    objective = 0
    
    for asset_name, asset_data in assets_scenarios_data.items():
        
        criticality = asset_data.get("criticality", 1.0 )
        
        for scenario_name, scenario_info in asset_data["scenarios"].items():
            
            risk_value = scenario_info["asset_risk_I"]
            
            
            objective += (criticality * risk_value) * decision_vars[asset_name][scenario_name]

            
        
        
    model += objective, "Minimize_Integrity_Risk_Weighted_by_Criticality"
    

def define_availability_objective_function(decision_vars, assets_scenarios_data, model):
    """
    Define la función objetivo para minimizar riesgo de disponibilidad ponderado.

    Args:
        decision_vars: Diccionario con variables de decisión por activo y escenario.
        assets_scenarios_data: Diccionario con escenarios enriquecidos por activo.
        model: Instancia del modelo de optimización de PuLP.

    Returns:
        None. La función objetivo se agrega directamente al modelo.
    """
    
    objective = 0
    
    for asset_name, asset_data in assets_scenarios_data.items():
        
        criticality = asset_data.get("criticality", 1.0 )
        
        for scenario_name, scenario_info in asset_data["scenarios"].items():
            
            risk_value = scenario_info["asset_risk_A"]
            
            
            objective += (criticality * risk_value) * decision_vars[asset_name][scenario_name]

            
        
        
    model += objective, "Minimize_Availability_Risk_Weighted_by_Criticality"
    


#===============================================[CONSTRAINTS]=============================================
def unique_cm_per_asset_constraint(decision_vars, model):

    """
    Agrega la restricción de que solo se puede seleccionar un escenario (contramedida) por activo.
    
    Args:
        decision_vars: Diccionario con variables de decisión por activo y escenario.
        model: Instancia del modelo de optimización de PuLP.
    
    Returns:
        None. Las restricciones se agregan directamente al modelo.
    """
    
    for asset_name, asset_data in decision_vars.items():
        
        constraint = pulp.lpSum([asset_data[scenario] for scenario in asset_data]) == 1
        
        model += constraint, f"Unique_CM_for_{asset_name}"
        
def budget_constraint(decision_vars, assets_scenarios_data, budget, model):
    """
    Agrega la restricción de presupuesto total para las contramedidas seleccionadas.
    
    Args:
        decision_vars: Diccionario con variables de decisión por activo y escenario.
        assets_scenarios_data: Diccionario con escenarios enriquecidos por activo.
        budget: Presupuesto total disponible para contramedidas.
        model: Instancia del modelo de optimización de PuLP.
    
    Returns:
        None. La restricción se agrega directamente al modelo.
    """
    
    total_cost = 0
    
    for asset_name, asset_info in assets_scenarios_data.items():
        
        for scenario_name, scenario_data in asset_info["scenarios"].items():
            
            cost = scenario_data["cost"]
            total_cost += cost * decision_vars[asset_name][scenario_name]
    
    model += total_cost <= budget, "Budget_Constraint"
    
    
def time_constraint(decision_vars, assets_scenarios_data, max_time_hours, model):
    """
    Agrega restricciones de tiempo máximo de despliegue por escenario.
    Se impide seleccionar escenarios cuya contramedida excede el límite permitido.

    Args:
        decision_vars: Diccionario con variables de decisión por activo y escenario.
        assets_scenarios_data: Diccionario con escenarios enriquecidos por activo.
        max_time_hours: Tiempo máximo permitido para desplegar una contramedida.
        model: Instancia del modelo de optimización de PuLP.

    Returns:
        None. Las restricciones se agregan directamente al modelo.
    """
    for asset_name, asset_info in assets_scenarios_data.items():
        for scenario_name, scenario_data in asset_info["scenarios"].items():
            time_hours = scenario_data["time_hours"]
            
            # Se bloquean escenarios que superan el tiempo máximo permitido
            if time_hours > max_time_hours:
                model += decision_vars[asset_name][scenario_name] == 0, f"Time_Limit_{asset_name}_{scenario_name}"
    
    
    
#==============================================[OPTIMIZATION PROBLEM SOLVING]=============================================
def solve_optimization_problem(decision_vars, assets_scenarios_data ,model, budget, report_data = None):
    """
    Resuelve el problema de optimización utilizando el solver de PuLP.
    
    Args:
        decision_vars: Diccionario con variables de decisión por activo y escenario.
        assets_scenarios_data: Diccionario con escenarios enriquecidos por activo.
        model: Instancia del modelo de optimización de PuLP.
        budget: Presupuesto total disponible para contramedidas.
        report_data: Datos del informe para contextualizar la solución.

    Returns:
        Diccionario con estado, riesgo, coste y decisiones seleccionadas.
    """
    
    if report_data is None:
        report_data = load_report_data()
    
    model.solve(pulp.PULP_CBC_CMD(msg=0))
    
    status = pulp.LpStatus[model.status]
    print(f"Status: {status}")
    
    if status != "Optimal":
        print(f"[WARN] Solución no óptima: {status}")
    
    
    # Se calcula la suma de criticidades para normalizar el riesgo objetivo
    total_criticality = sum(
        asset_info.get("criticality", 1.0) 
        for asset_info in assets_scenarios_data.values()
    )
    
    
    
    optimal_risk_weighted = pulp.value(model.objective)
    optimal_risk_normalized = optimal_risk_weighted / total_criticality
    
    print(f"Riesgo global mínimo (ponderado): {optimal_risk_weighted:.4f}")
    print(f"Riesgo global mínimo (normalizado): {optimal_risk_normalized:.4f}")
    print(f"Suma de criticidades: {total_criticality:.4f}")
    
    
    # Se construye la estructura de salida con métricas globales y decisiones por activo
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
    
    # Se registra el escenario seleccionado para cada activo
    for asset_name, scenarios in decision_vars.items():
        for scenario_name, scenario_var in scenarios.items():
            if scenario_var.varValue == 1:
                scenario_data = assets_scenarios_data[asset_name]["scenarios"][scenario_name]
                criticality = assets_scenarios_data[asset_name]["criticality"]
                
                solution["assets_decisions"][asset_name] = {
                    "scenario": scenario_name,
                    "countermeasure": scenario_data["countermeasure"],
                    "risk_total": scenario_data["risk_total"],
                    "asset_risk_C": scenario_data["asset_risk_C"],
                    "asset_risk_I": scenario_data["asset_risk_I"],
                    "asset_risk_A": scenario_data["asset_risk_A"],
                    "criticality": criticality,
                    "weighted_risk": scenario_data["risk_total"] * criticality,
                    "cost": scenario_data["cost"],
                    "time_hours": scenario_data["time_hours"]
                }
                
                solution["total_cost"] += scenario_data["cost"]
    solution["total_cost_used_percent"] = str((solution["total_cost"] / budget) * 100 if budget != 0 else 0) + "%"
   
    # Se muestra un resumen operativo de contramedidas seleccionadas
    print("\n" + "="*80)
    print("RESUMEN DE CONTRAMEDIDAS SELECCIONADAS")
    print("="*80)
    cms_count = {}
    for asset_name, decision in solution["assets_decisions"].items():
        cm = decision["countermeasure"]
        if cm not in cms_count:
            cms_count[cm] = []
        cms_count[cm].append(asset_name)
    
    for cm, assets in sorted(cms_count.items()):
        print(f"\n{cm.upper()}: {len(assets)} activos")
        for asset in assets:
            cost = solution["assets_decisions"][asset]["cost"]
            time = solution["assets_decisions"][asset]["time_hours"]
            risk = solution["assets_decisions"][asset]["risk_total"]
            print(f"  - {asset}: Riesgo={risk:.4f}, Coste=${cost:,}, Tiempo={time}h")
    
    print("\n" + "="*80)
    print("La solución óptima encontrada es:")
    print("="*80)
    print(json.dumps(solution, indent=4))
                
    return solution


#======================================================[LP INTEGRATION]======================================================
def build_optimization_problem(assets_scenarios_data, decision_vars, budget = 50000, max_time_hours = 210):
    """
    Construye el problema de optimización global.
    Se define el objetivo global y se añaden restricciones comunes.
    
    Args:
        assets_scenarios_data: Diccionario con escenarios enriquecidos por activo.
        decision_vars: Variables de decisión para cada activo y escenario.
        budget: Presupuesto total disponible para contramedidas.
        max_time_hours: Tiempo máximo permitido para desplegar una contramedida.

    Returns:
        Modelo de optimización configurado.
    """
    # Se crea el modelo de minimización y se añaden objetivo y restricciones
    model = pulp.LpProblem("Minimize_Global_Risk", pulp.LpMinimize)
    
    define_global_objective_function( decision_vars, assets_scenarios_data, model)
    
    unique_cm_per_asset_constraint(decision_vars, model)
    budget_constraint(decision_vars, assets_scenarios_data, budget, model)
    time_constraint(decision_vars, assets_scenarios_data, max_time_hours, model)
    
    return model

def setup_optimization_problem( report_data, budget = 50000, max_time_hours = 210):
    """
    Prepara datos, variables y modelo de optimización global.

    Args:
        report_data: Diccionario del reporte de riesgo. Si es None, se carga desde disco.
        budget: Presupuesto total disponible para contramedidas.
        max_time_hours: Tiempo máximo permitido para desplegar una contramedida.

    Returns:
        Tuple con escenarios enriquecidos, variables de decisión y modelo configurado.
    """
    
    if report_data is None:
        report_data = load_report_data()
   
    cm_config = load_countermeasures_config()
    
    assets_scenarios_data = extract_asset_scenarios_info(report_data, cm_config)
    
    decision_vars = create_decision_variables(assets_scenarios_data)
    
    model = build_optimization_problem(assets_scenarios_data, decision_vars, budget, max_time_hours)
    
    return assets_scenarios_data, decision_vars, model


#===============================================[MULTI-OBJECTIVE OPTIMIZATION]=============================================
def build_optimization_problem_with_objective(assets_scenarios_data, decision_vars, objective_func, budget=50000, max_time_hours=210):
    """
    Construye un problema de optimización con una función objetivo específica.
    
    Args:
        assets_scenarios_data: Escenarios enriquecidos de cada activo.
        decision_vars: Variables de decisión del modelo.
        objective_func: Función objetivo que se desea utilizar.
        budget: Presupuesto total disponible para contramedidas.
        max_time_hours: Tiempo máximo permitido para desplegar una contramedida.
    
    Returns:
        Modelo de optimización configurado.
    """
    model = pulp.LpProblem("Optimization_Problem", pulp.LpMinimize)
    
    # Se aplica el objetivo elegido y las restricciones comunes
    objective_func(decision_vars, assets_scenarios_data, model)
    
    unique_cm_per_asset_constraint(decision_vars, model)
    budget_constraint(decision_vars, assets_scenarios_data, budget, model)
    time_constraint(decision_vars, assets_scenarios_data, max_time_hours, model)
    
    return model


def solve_optimization_problems(assets_scenarios_data, objective_type="all", budget=50000, max_time_hours=210):
    """
    Resuelve uno o múltiples problemas de optimización según el objetivo especificado.
    
    Args:
        assets_scenarios_data: Diccionario con escenarios enriquecidos por activo.
        objective_type: Objetivo a resolver: all, global, confidentiality, integrity o availability.
        budget: Presupuesto total disponible para contramedidas.
        max_time_hours: Tiempo máximo permitido para desplegar una contramedida.
    
    Returns:
        Diccionario con la solución o soluciones calculadas.
    """
    
    # Se mapean los objetivos disponibles para seleccionar dinámicamente la función objetivo
    objectives_map = {
        "global": define_global_objective_function,
        "confidentiality": define_confidentiality_objective_function,
        "integrity": define_integrity_objective_function,
        "availability": define_availability_objective_function
    }
    
    # Se almacenan las soluciones generadas por objetivo
    results = {}
    
    # Se resuelven todos los objetivos si se solicita una comparativa completa
    if objective_type == "all":
        print("\n" + "="*80)
        print("RESOLVIENDO LOS 4 PROBLEMAS DE OPTIMIZACIÓN")
        print("="*80)
        
        for obj_name, obj_func in objectives_map.items():
            print(f"\n>>> Resolviendo: {obj_name.upper()}")
            print("-"*80)
            
            # Se crean variables independientes para cada modelo de optimización
            decision_vars_copy = create_decision_variables(assets_scenarios_data)
            
            model = build_optimization_problem_with_objective(
                assets_scenarios_data, decision_vars_copy, obj_func, budget, max_time_hours
            )
            
            results[obj_name] = solve_optimization_problem(
                decision_vars_copy, assets_scenarios_data, model, budget
            )
    
        
    # Se resuelve un único objetivo cuando se solicita uno concreto
    else:
        if objective_type not in objectives_map:
            raise ValueError(f"Objetivo no válido: {objective_type}. Opciones: {list(objectives_map.keys())}")
        
        print(f"\n Resolviendo: {objective_type.upper()}")
        print("-"*80)
        
        decision_vars_copy = create_decision_variables(assets_scenarios_data)
        
        model = build_optimization_problem_with_objective(
            assets_scenarios_data, decision_vars_copy, objectives_map[objective_type], 
            budget, max_time_hours
        )
        results[objective_type] = solve_optimization_problem(
            decision_vars_copy, assets_scenarios_data, model, budget
        )
    
    save_solution(results)
    
    return results


def save_solution(results):
    """
    Guarda una comparativa de todas las soluciones en JSON.
    
    Args:
        results: Diccionario con todas las soluciones calculadas.

    Returns:
        None. Se escribe el archivo optimization_solution.json.
    """
    comparison_path = Path(__file__).parent.parent / "reporting" / "optimization_solution.json"
    
    with open(comparison_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=4)
    
    print(f"\nSolución guardada en: {comparison_path}")
 
 


