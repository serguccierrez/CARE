#====================================[IMPORTS]====================================#
import argparse

from src.cli import attack, dashboard, db, run_blocked, welcome
import src.graph.grafo as grafo
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
        "selected_asset": None,
        "selected_ttps": [],
        "selected_confidences": None,
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
        print(f"Error: el escenario '{scenario_name}' no existe.")
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
        print(f"Error: el escenario '{scenario_name}' no existe.")
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
        print(f"Error: ya existe un escenario con el nombre '{scenario_name}'.")
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
        print(f"Error: el escenario '{scenario_name}' no existe.")
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
    return runner.main(scenario_name, context=context)
        
def handle_attack_select(args):
    context = json_load_context()
    context["selected_asset"] = args.asset if hasattr(args.asset, "asset") else None
    context["selected_ttps"] = args.ttp if hasattr(args.ttp, "ttp") else None
    context["selected_confidence"] = args.confidence if hasattr(args.confidence, "confidence") else None
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
        "CLI principal para renderizar las vistas del sistema."
    )
)
subparsers = parser.add_subparsers(title="Commands", dest="command")

#{INIT}#
# Comando para renderizar la vista de bienvenida
asset_parser = subparsers.add_parser(
    "init",
    help="Render the CARE welcome view",
    description="Muestra la pantalla principal de bienvenida de CARE.",
)
asset_parser.set_defaults(handler=render_init_view)

#{DATABASE}#
# Comando para renderizar la vista de base de datos
db_parser = subparsers.add_parser(
    "db",
    help="Render the database management view",
    description="Muestra la interfaz CLI para gestionar escenarios y datos.",
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
    help="Nombre del escenario a cargar",
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
    help="Nombre del escenario a eliminar",
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
    help="Nombre del escenario a crear",
    required=True
)

db_create_parser.add_argument(
    "--description",
    help="Descripción opcional del escenario",
    required=False
)

db_create_parser.add_argument(
    "--source",
    help="Archivo Excel fuente del escenario (opcional)",
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
    help="Nombre del escenario para listar sus activos",
    required=True
)
db_list_parser.set_defaults(handler=handle_db_list)


#{ATTACK}#
# Comando para renderizar la vista de ataque
attack_parser = subparsers.add_parser(
    "attack",
    help="Render the attack operations view",
    description="Muestra la interfaz operativa de simulacion e inyeccion de ataques.",
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
    help="Nombre del activo a seleccionar para operaciones de ataque",
    required=False
)

# Comando para seleccionar un TTP concreto
attack_select_parser.add_argument(
    "--ttp",
    help="Nombre del ttp a seleccionar para operaciones de ataque",
    required=False
)


attack_select_parser.add_argument(
    "--confidence",
    help="Nivel de confianza para la seleccion del TTP (opcional)",
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
    help="Ejecutar una simulacion de ataque con configuracion aleatoria",
    action="store_true"
)

attack_run_parser.set_defaults(handler=handle_attack_run)




#{DASHBOARD}#
# Comando para renderizar la vista dashboard
dashboard_parser = subparsers.add_parser(
    "dashboard",
    help="Render the analysis dashboard view",
    description="Muestra el dashboard con el resumen del analisis de riesgos.",
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

