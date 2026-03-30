#====================================[IMPORTS]====================================#
import argparse

from src.cli import attack, dashboard, db, run_blocked, welcome
import src.graph.grafo as grafo
import src.cyberrecom.mitre as mitre
import src.database.load_data as load_data
import src.cyberrecom.runner as runner
from pathlib import Path

import json


#====================================[CONSTANTS]====================================#
DB_PATH = Path(__file__).parent.parent / "database" / "tfg_catalog.db"
global active_scenario



#=====================================[AUXILIARY FUNCTIONS]====================================#
def context_JSON_initialization():
    context = {
        "active_scenario": None,
        "mode": None,
        "selected_asset":[],
        "selected_ttps": [],
        "selected_confidences": [],
    }
    return context

def json_dump_context(context: dict):
    '''Función encargadad de recibir el dict del contexto y guardarlo en un .JSON file'''
    context_path = Path(__file__).parent / "context.json"
    with open(context_path, "w") as f:
        json.dump(context, f, indent=4)
        
def json_load_context() -> dict:
    '''Función encargada de cargar el contexto desde un .JSON file en /src/cli y devolverlo como dict'''
    context_path = Path(__file__).parent / "context.json"
    with open(context_path, "r") as f:
        context = json.load(f)
    return context
    
    
#====================================[COMMAND CALLBACKS]====================================#

#{INIT}#
def render_init_view(args: argparse.Namespace) -> None:
    """
    Renderiza la vista de bienvenida principal de CARE.
    """
    welcome.main()
    context = context_JSON_initialization()
    json_dump_context(context)


#{DATABASE}#
def render_db_view(scenario_name, show_assets = False) -> None:
    """
    Renderiza la vista de gestion de base de datos y escenarios.
    """
    context = json_load_context()
    
    if context["active_scenario"] != None:
        scenario_name = context["active_scenario"]
        
    db.main(scenario_name, show_assets)

def handle_db_load(args):
    scenario_name = args.scenario

    # Validar que existe
    scenarios = grafo.list_scenarios(str(DB_PATH))
    scenario_names = [scenario[1] for scenario in scenarios]

    if scenario_name not in scenario_names:
       run_blocked.main(
        title="CARE / INVALID SCENARIO",
        header="Selected Scenario Not Found",
        description="The requested scenario does not exist.",
        action_title="Suggested action",
        action_text='care db load --scenario "<valid_scenario_name>"',
        footer="Verify the scenario name and try again.",
        
    )
       return
    

    # Guardarlo como escenario activo
    context = json_load_context()
    context["active_scenario"] = scenario_name
    json_dump_context(context)

    # Rerenderizar la vista DB marcándolo
    render_db_view(scenario_name)

def handle_db_delete(args):
    scenario_name = args.scenario

    # Validar que existe
    scenarios = grafo.list_scenarios(str(DB_PATH))
    scenario_names = [scenario[1] for scenario in scenarios]

    if scenario_name not in scenario_names:
        run_blocked.main(
            title="CARE / INVALID SCENARIO",
            header="Selected Scenario Not Found",
            description="The requested scenario does not exist.",
            action_title="Suggested action",
            action_text='care db delete --scenario "<valid_scenario_name>"',
            footer="Verify the scenario name and try again.",
        )
        return

    # Eliminarlo de la base de datos
    grafo.delete_scenario(str(DB_PATH), scenario_name)

    # Rerenderizar la vista DB sin el escenario eliminado
    render_db_view(None)


def handle_db_create(args):
    scenario_name = args.scenario
    scenario_description = args.description if hasattr(args, "description") else None
    source_file = args.source if hasattr(args, "source") else None

    # Validar que no existe ya un escenario con ese nombre
    scenarios = grafo.list_scenarios(str(DB_PATH))
    scenario_names = [scenario[1] for scenario in scenarios]

    if scenario_name in scenario_names:
        run_blocked.main(
            title="CARE / INVALID SCENARIO",
            header="Selected Scenario Already Exists",
            description="A scenario with the same name already exists.",
            action_title="Suggested action",
            action_text='care db create --scenario "<unique_scenario_name>"',
            footer="Choose a different scenario name and try again.",
        )
        return

    if  source_file == None:
        # Crear un nuevo escenario vacío en la base de datos
        load_data.create_empty_scenario(DB_PATH, scenario_name, scenario_description, source_file)

    load_data.load_and_insert_data(source_file, DB_PATH, scenario_name, scenario_description)

    
    # Rerenderizar la vista DB con el nuevo escenario
    render_db_view(scenario_name)

def handle_db_list(args):
    scenario_name = args.scenario

    # Validar que existe
    scenarios = grafo.list_scenarios(str(DB_PATH))
    scenario_names = [scenario[1] for scenario in scenarios]

    if scenario_name not in scenario_names:
        run_blocked.main(
            title="CARE / INVALID SCENARIO",
            header="Selected Scenario Not Found",
            description="The requested scenario does not exist.",
            action_title="Suggested action",
            action_text='care db asset-list --scenario "<valid_scenario_name>"',
            footer="Verify the scenario name and try again.",
        )
        return

    # Listar sus activos
    assets = grafo.list_assets_by_scenario(str(DB_PATH), scenario_name)

    render_db_view(scenario_name, show_assets=True)


#{ATTACK}#
def render_attack_view(args: argparse.Namespace) -> None:
    """
    Renderiza la vista operativa para simulacion e inyeccion de ataques.
    """
    context = json_load_context()
    
    attack.main(context)
    
def handle_attack_run(args):
    context = json_load_context()
    scenario_name = context.get("active_scenario")

    if not scenario_name:
        run_blocked.main()
        return

    if args.random:
        context["mode"] = "random"
    elif not context.get("mode"):
        context["mode"] = "controlled"

    json_dump_context(context)
    
    runner.main(scenario_name, context=context)
    
    return dashboard.main()
        
def handle_attack_select(args):
    context = json_load_context()
    
    scenario_name = context["active_scenario"]
    assets = grafo.list_assets_by_scenario(str(DB_PATH), scenario_name)

    asset_ids = [asset[2] for asset in assets]
    
    
    
    if args.asset and args.asset not in asset_ids:
        run_blocked.main(
        title="CARE / INVALID ASSET",
        header="Selected Asset Not Found",
        description="The requested asset does not exist in the active scenario.",
        action_title="Suggested action",
        action_text='care attack select --asset "<valid_asset_id>"',
        footer="Verify the asset ID and try again.",
)
        return
    elif args.ttp and not mitre.check_ttp_exists(args.ttp):
        run_blocked.main(
        title="CARE / INVALID TTP",
        header="Selected TTP Not Found",
        description="The requested TTP does not exist in MITRE ATT&CK.",
        action_title="Suggested action",
        action_text='care attack select --ttp "<valid_ttp_id>"',
        footer="Verify the TTP ID and try again.",
)        
        return
    elif args.confidence and (not isinstance(args.confidence, float) or not (0.0 <= args.confidence <= 1.0)):
        run_blocked.main(
        title="CARE / INVALID CONFIDENCE",
        header="Invalid Confidence Value",
        description="The confidence value must be a float between 0.0 and 1.0.",
        action_title="Suggested action",
        action_text='care attack select --confidence <valid_confidence_value>',
        footer="Verify the confidence value and try again.",
)
        return
    
    context["selected_asset"].append(args.asset) if hasattr(args, "asset") else None
    context["selected_ttps"].append(args.ttp) if hasattr(args, "ttp") else None
    context["selected_confidences"].append(args.confidence) if hasattr(args, "confidence") else None
    context["mode"] = "controlled"
    
    json_dump_context(context)
    
    return attack.main(context)



#{DASHBOARD}#
def render_dashboard_view(args: argparse.Namespace) -> None:
    """
    Renderiza la vista dashboard con el resumen del analisis de riesgos.
    """
    dashboard.main()


#====================================[COMMAND LINE ARGUMENTS]====================================#
parser = argparse.ArgumentParser(
    description=(
        "CARE - Cyber Action Recommendation Engine. "
        "Main CLI for rendering the system views."
    )
)
subparsers = parser.add_subparsers(title="Commands", dest="command")

#{INIT}#
# Comando para renderizar la vista de bienvenida
asset_parser = subparsers.add_parser(
    "init",
    help="Render the CARE welcome view",
    description="Render the main CARE welcome screen.",
)
asset_parser.set_defaults(handler=render_init_view)

#{DATABASE}#
# Comando para renderizar la vista de base de datos
db_parser = subparsers.add_parser(
    "db",
    help="Render the database management view",
    description="Render the CLI interface for managing scenarios and data.",
)
db_parser.set_defaults(handler=render_db_view)

db_subparsers = db_parser.add_subparsers(dest="db_command")

# Comando para cargar un escenario específico
db_load_parser = db_subparsers.add_parser(
    "load",
    help="Load a scenario"
)
db_load_parser.add_argument(
    "--scenario",
    help="Name of the scenario to load",
    required=True
)
db_load_parser.set_defaults(handler=handle_db_load)

# Comando para borrar un escenario específico
db_delete_parser = db_subparsers.add_parser(
    "delete",
    help="Delete a scenario"
)
db_delete_parser.add_argument(
    "--scenario",
    help="Name of the scenario to delete",
    required=True
)
db_delete_parser.set_defaults(handler=handle_db_delete)

# Comando para crear un nuevo scenario
db_create_parser = db_subparsers.add_parser(
    "create",
    help="Create a new scenario from an Excel asset/dependency catalog"
)

db_create_parser.add_argument(
    "--scenario",
    help="Name of the scenario to create",
    required=True
)

db_create_parser.add_argument(
    "--description",
    help="Optional scenario description",
    required=False
)

db_create_parser.add_argument(
    "--source",
    help="Source Excel file for the scenario (optional)",
    required=False
)

db_create_parser.set_defaults(handler=handle_db_create)


# Comando para listar todos los activos de un escenario específico
db_list_parser = db_subparsers.add_parser(
    "asset-list",
    help="List all assets for a scenario"
)

db_list_parser.add_argument(
    "--scenario",
    help="Name of the scenario whose assets will be listed",
    required=True
)
db_list_parser.set_defaults(handler=handle_db_list)


#{ATTACK}#
# Comando para renderizar la vista de ataque
attack_parser = subparsers.add_parser(
    "attack",
    help="Render the attack operations view",
    description="Render the operational interface for attack simulation and injection.",
)
attack_parser.set_defaults(handler=render_attack_view)

attack_asset_parser = attack_parser.add_subparsers(dest="attack_command")

# Comando para seleccionar un activo concreto
attack_select_parser = attack_asset_parser.add_parser(
    "select",
    help="Select a specific asset for attack operations"
)

attack_select_parser.add_argument(
    "--asset",
    help="Asset ID to select for attack operations",
    required=False
)

# Comando para seleccionar un TTP concreto
attack_select_parser.add_argument(
    "--ttp",
    help="TTP ID to select for attack operations",
    required=False
)


attack_select_parser.add_argument(
    "--confidence",
    help="Confidence level for the selected TTP (optional)",
    type=float,
    required=False,
)

attack_select_parser.set_defaults(handler=handle_attack_select)

# Coamando para ejecutar un ataque
attack_run_parser = attack_asset_parser.add_parser(
    "run",
    help="Execute an attack simulation based on selected configuration"
)

# Comando para ejecutar un ataque con configuracion aleatoria
attack_run_parser.add_argument(
    "--random",
    help="Run an attack simulation with a random configuration",
    action="store_true"
)

attack_run_parser.set_defaults(handler=handle_attack_run)




#{DASHBOARD}#
# Comando para renderizar la vista dashboard
dashboard_parser = subparsers.add_parser(
    "dashboard",
    help="Render the analysis dashboard view",
    description="Render the dashboard with the risk analysis summary.",
)
dashboard_parser.set_defaults(handler=render_dashboard_view)


def main() -> None:
    """
    Punto de entrada principal de la CLI.

    Resuelve el comando solicitado y renderiza la vista correspondiente
    dentro del modulo `src/cli`.
    """
    args = parser.parse_args()

    if not hasattr(args, "handler"):
        parser.print_help()
        return

    args.handler(args)


if __name__ == "__main__":
    main()

