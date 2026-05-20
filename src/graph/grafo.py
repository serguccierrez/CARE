"""
Se cargan activos y dependencias desde SQLite para construir grafos con NetworkX.
Se permite analizar escenarios, dominios y propagación de compromiso entre activos.
"""
from pathlib import Path
import sqlite3
import json
from matplotlib.pylab import rint
import networkx as nx

#===============================================[CONSTANTS]===============================================
def load_constants() -> dict:
    """
    Carga las constantes generales desde el archivo JSON de configuración.
    Se leen dominios, tipos de dependencias y tipos de activos.

    Args:
        None.
    
    Returns:
        Diccionario con las constantes cargadas desde el archivo JSON.
    """
    config_path = Path(__file__).parent.parent.parent / "Configs" / "constants.json"
    with open(config_path, 'r', encoding='utf-8') as f:
        config = json.load(f)
    return config

def load_dependency_probabilities() -> dict:
    """
    Carga las probabilidades de propagación por táctica y tipo de dependencia.
    Se obtiene la matriz de dependencias desde el archivo JSON de configuración.

    Args:
        None.

    Returns:
        Diccionario con las probabilidades de propagación de compromisos.
    """
    config_path = Path(__file__).parent.parent.parent / "Configs" / "dependency_matrix.json"
    with open(config_path, 'r', encoding='utf-8') as f:
        config = json.load(f)
    return config

# Se carga la configuración necesaria para construir y analizar grafos
_config = load_constants()
DOMINIOS = _config["dominios"]
DEPENDENCIES_TYPES = _config["dependencies_types"]
ASSET_TYPES = _config["asset_types"]
DEPENDENCY_MATRIX = load_dependency_probabilities()


#===============================================[DATABASE_FUNCTIONS]===============================================
def get_domain_assets(db_path: str, scenario_pk: int, domain: str):
    """
    Obtiene y retorna los activos del dominio especificado para un escenario concreto.
    Se consultan únicamente los activos asociados al scenario_pk recibido.

    Args:
        db_path: Ruta de la base de datos SQLite.
        scenario_pk: Clave primaria del escenario analizado.
        domain: Dominio del que se desean obtener los activos.

    Returns:
        Lista de tuplas con los activos del dominio.
    """
    con = sqlite3.connect(db_path)
    try:
        cur = con.cursor()
        cur.execute("""
            SELECT *
            FROM assets
            WHERE scenario_fk = ? AND domain = ?;
        """, (scenario_pk, domain))
        rows = cur.fetchall()
        return rows
    finally:
        con.close()

def get_domain_intra_dependencies(db_path: str, scenario_pk: int, domain: str):
    """
    Obtiene y retorna las dependencias internas del dominio para un escenario concreto.
    Se seleccionan dependencias cuyo origen y destino pertenecen al mismo dominio.

    Args:
        db_path: Ruta de la base de datos SQLite.
        scenario_pk: Clave primaria del escenario analizado.
        domain: Dominio del que se desean obtener dependencias internas.

    Returns:
        Lista de tuplas con dependencias internas del dominio.
    """
    con = sqlite3.connect(db_path)
    try:
        cur = con.cursor()
        cur.execute("""
            SELECT *
            FROM dependencies
            WHERE scenario_fk = ?
              AND from_asset IN (
                  SELECT asset_id
                  FROM assets
                  WHERE scenario_fk = ? AND domain = ?
              )
              AND to_asset IN (
                  SELECT asset_id
                  FROM assets
                  WHERE scenario_fk = ? AND domain = ?
              );
        """, (scenario_pk, scenario_pk, domain, scenario_pk, domain))
        rows = cur.fetchall()
        return rows
    finally:
        con.close()
        
def get_domain_inter_dependencies(db_path: str, scenario_pk: int, domain: str):
    """
    Obtiene dependencias inter-dominio que involucran al dominio especificado.
    Se incluyen los dominios de origen y destino para facilitar el análisis global.

    Args:
        db_path: Ruta de la base de datos SQLite.
        scenario_pk: Clave primaria del escenario analizado.
        domain: Dominio usado como referencia de la consulta.

    Returns:
        Lista de tuplas con dependencias inter-dominio y sus dominios asociados.
    """
    con = sqlite3.connect(db_path)
    try:
        cur = con.cursor()
        cur.execute("""
            SELECT d.*, a1.domain as from_domain, a2.domain as to_domain
            FROM dependencies d
            LEFT JOIN assets a1
              ON d.scenario_fk = a1.scenario_fk AND d.from_asset = a1.asset_id
            LEFT JOIN assets a2
              ON d.scenario_fk = a2.scenario_fk AND d.to_asset = a2.asset_id
            WHERE d.scenario_fk = ?
              AND (
                    (a1.domain = ? AND a2.domain <> ?)
                 OR (a2.domain = ? AND a1.domain <> ?)
              );
        """, (scenario_pk, domain, domain, domain, domain))
        rows = cur.fetchall()
        return rows
    finally:
        con.close()
        


def list_scenarios(db_path: str) -> list[tuple]:
    """
    Retorna todos los escenarios disponibles en la base de datos.
    Se ordenan por clave primaria para mantener una salida estable.

    Args:
        db_path: Ruta a la base de datos SQLite.

    Returns:
        Lista de tuplas con los escenarios disponibles.
    """
    con = sqlite3.connect(db_path)
    try:
        cur = con.cursor()
        cur.execute("""
            SELECT scenario_pk, scenario_name, description, source_file, created_at
            FROM scenarios
            ORDER BY scenario_pk;
        """)
        rows = cur.fetchall()
        return rows
    finally:
        con.close()
        
        
def delete_scenario(db_path: str, scenario_name: str):
    """
    Elimina un escenario específico de la base de datos, junto con sus activos y dependencias asociadas.
    Se borran primero las relaciones dependientes y finalmente el escenario.

    Args:
        db_path: Ruta a la base de datos SQLite.
        scenario_name: Nombre del escenario a eliminar.

    Returns:
        None. Imprime mensajes de éxito o error según corresponda.
    """
    con = sqlite3.connect(db_path)
    try:
        cur = con.cursor()
        # Se obtiene el scenario_pk del escenario a eliminar
        cur.execute("""
            SELECT scenario_pk
            FROM scenarios
            WHERE scenario_name = ?;
        """, (scenario_name,))
        row = cur.fetchone()
        
        if row is None:
            print(f"Error: El escenario '{scenario_name}' no existe en la base de datos.")
            return

        # Se conserva la clave primaria para eliminar los datos asociados
        scenario_pk = row[0]
        
        # Se eliminan dependencias, activos y escenario en orden
        cur.execute("""
            DELETE FROM dependencies
            WHERE scenario_fk = ?;
        """, (scenario_pk,))
        
        cur.execute("""
            DELETE FROM assets
            WHERE scenario_fk = ?;
        """, (scenario_pk,))
        
        cur.execute("""
            DELETE FROM scenarios
            WHERE scenario_pk = ?;
        """, (scenario_pk,))
        
        con.commit()
        print(f"Escenario '{scenario_name}' y sus datos asociados han sido eliminados.")
        
    finally:
        con.close()
        
        
def get_scenario_pk(db_path: str, scenario_name: str = None):
    """
    Obtiene la clave primaria de un escenario.
    Se busca por nombre si se proporciona, o se usa el último escenario creado.

    Args:
        db_path: Ruta a la base de datos SQLite.
        scenario_name: Nombre opcional del escenario a buscar.

    Returns:
        Clave primaria del escenario encontrado.
    """
    con = sqlite3.connect(db_path)
    try:
        cur = con.cursor()

        # Se usa el último escenario creado cuando no se proporciona nombre
        if not scenario_name:
            cur.execute("""
                SELECT scenario_pk, scenario_name
                FROM scenarios
                ORDER BY created_at DESC
                LIMIT 1;
            """)
            row = cur.fetchone()

            if row is None:
                raise ValueError("No hay escenarios en la base de datos.")

            scenario_pk, scenario_name = row
            print(f"[INFO] Usando último escenario: '{scenario_name}' (pk={scenario_pk})")

            return scenario_pk

        # Se busca el escenario concreto indicado por nombre
        cur.execute("""
            SELECT scenario_pk
            FROM scenarios
            WHERE scenario_name = ?;
        """, (scenario_name,))

        row = cur.fetchone()

        if row is None:
            raise ValueError(f"El escenario '{scenario_name}' no existe en la base de datos.")

        return row[0]

    finally:
        con.close()
        
def list_assets_by_scenario(db_path: str, scenario_name: str):
    """
    Retorna todos los activos asociados a un escenario concreto.
    Se ordenan por dominio e identificador de activo.

    Args:
        db_path: Ruta a la base de datos SQLite.
        scenario_name: Nombre del escenario.

    Returns:
        Lista de tuplas con los activos del escenario.
    """
    con = sqlite3.connect(db_path)
    
    scenario_pk = get_scenario_pk(db_path, scenario_name)
    
    try:
        cur = con.cursor()
        cur.execute("""
            SELECT *
            FROM assets
            WHERE scenario_fk = ?
            ORDER BY domain, asset_id;
        """, (scenario_pk,))
        rows = cur.fetchall()
        return rows
    finally:
        con.close()

        
#===============================================[GRAPH_FUNCTIONS]===============================================
def build_intra_domain_graph(domain: str, assets_rows, deps_rows) -> nx.DiGraph:
    """
    Construye y retorna un grafo dirigido de NetworkX para el dominio especificado.
    Se incorporan activos como nodos y dependencias internas como aristas ponderadas.

    Args:
        domain: Dominio para el cual se construye el grafo.
        assets_rows: Tuplas con los activos del dominio.
        deps_rows: Tuplas con las dependencias internas del dominio.

    Returns:
        Grafo dirigido de NetworkX con activos y dependencias del dominio.
    """
    G = nx.DiGraph(domain=domain)

    # Se agregan nodos a partir de los activos del dominio
    for asset in assets_rows:
        asset_pk, scenario_fk ,asset_id, name, asset_type, dom, criticality, cia_c, cia_i, cia_a, operational_state = asset
        
        G.add_node(
            asset_id,
            name=name,
            asset_type=asset_type,
            domain=dom,
            criticality=float(criticality),
            cia_c=float(cia_c),
            cia_i=float(cia_i),
            cia_a=float(cia_a),
            operational_state=operational_state,
        )
        
    # Se agregan aristas a partir de las dependencias internas
    for dep in deps_rows:
        dep_pk, scenario_fk, dependency_id, from_asset, to_asset, dependency_type, cia_couple_c, cia_couple_i, cia_couple_a = dep[:9]
        
        cc = float(cia_couple_c)
        ci = float(cia_couple_i)
        ca = float(cia_couple_a)
        weight = (cc**2 + ci**2 + ca**2) ** 0.5

        G.add_edge(
            from_asset,
            to_asset,
            dependency_id=dependency_id,
            dependency_type=dependency_type,
            cia_couple_c=cc,
            cia_couple_i=ci,
            cia_couple_a=ca,
            weight=weight,
        )

    return G

def build_MDO_global_graph(all_assets, all_deps) -> nx.DiGraph:
    """
    Construye y retorna un grafo dirigido de NetworkX con todos los activos y dependencias.
    Se usa como representación global MDO del escenario completo.

    Args:
        all_assets: Tuplas con todos los activos acumulados del escenario.
        all_deps: Tuplas con todas las dependencias acumuladas del escenario.

    Returns:
        Grafo dirigido global con activos y dependencias del escenario.
    """
    G = nx.DiGraph(domain="MDO Global")

    # Se agregan los activos como nodos del grafo global
    for asset in all_assets:
        asset_pk, scenario_fk, asset_id, name, asset_type, dom, criticality, cia_c, cia_i, cia_a, operational_state = asset
        
        G.add_node(
            asset_id,
            name=name,
            asset_type=asset_type,
            domain=dom,
            criticality=float(criticality),
            cia_c=float(cia_c),
            cia_i=float(cia_i),
            cia_a=float(cia_a),
            operational_state=operational_state,
        )
        
    # Se agregan las dependencias como aristas del grafo global
    for dep in all_deps:
        # Se toman solo los campos base cuando la tupla incluye dominios al final
        dep_pk, scenario_fk, dependency_id, from_asset, to_asset, dependency_type, cia_couple_c, cia_couple_i, cia_couple_a = dep[:9]
        
        cc = float(cia_couple_c)
        ci = float(cia_couple_i)
        ca = float(cia_couple_a)
        weight = (cc**2 + ci**2 + ca**2) ** 0.5

        G.add_edge(
            from_asset, 
            to_asset,
            dependency_id=dependency_id,
            dependency_type=dependency_type,
            cia_couple_c=cc,
            cia_couple_i=ci,
            cia_couple_a=ca,
            weight=weight,
        )

    return G
    
    
def process_and_build_graph_domain(db_path: str,scenario_pk: int,domain: str,all_assets: list,all_deps_dict: dict) -> nx.DiGraph:
    """
    Procesa un dominio individual dentro de un escenario.
    Se obtienen activos y dependencias, se construye el grafo del dominio y se acumulan datos globales.

    Args:
        db_path: Ruta a la base de datos SQLite.
        scenario_pk: Clave primaria del escenario a procesar.
        domain: Dominio a procesar.
        all_assets: Lista acumuladora de activos de todos los dominios.
        all_deps_dict: Diccionario acumulador de dependencias, indexado por dep_pk.

    Returns:
        None. Los datos se acumulan en las estructuras recibidas por parámetro.
    """
    # Se muestran y acumulan los activos del dominio
    print(f"\n{'='*60}")
    print(f"Activos en el dominio '{domain}':")
    print(f"{'='*60}")
    
    assets = get_domain_assets(db_path, scenario_pk, domain)
    
    if assets:
        for asset in assets:
            # asset[1] = asset_id, asset[2] = name
            print(f"  - {asset[2]}: {asset[3]}")
            all_assets.append(asset)
    else:
        print(f"  --> No hay activos en {domain}")
    
    # Se muestran y acumulan las dependencias internas del dominio
    print(f"\n{'-'*60}")
    print(f"Dependencias internas en '{domain}':")
    print(f"{'-'*60}")
    
    intraDomainDeps = get_domain_intra_dependencies(db_path, scenario_pk, domain)
    
    if intraDomainDeps:
        for dep in intraDomainDeps:
            print(f"  {dep[3]} --> {dep[4]} ({dep[5]})")
            dep_pk = dep[0]
            if dep_pk not in all_deps_dict:
                all_deps_dict[dep_pk] = dep
    else:
        print(f"  --> No hay dependencias internas en {domain}")
        
    # Se construye el grafo intra-dominio para mostrar sus métricas básicas
    G = build_intra_domain_graph(domain, assets, intraDomainDeps)
    print(f"\n Grafo construido para '{domain}':")
    print(f"    - Nodos: {G.number_of_nodes()}")
    print(f"    - Aristas: {G.number_of_edges()}")
    
    # Se muestran y acumulan las dependencias inter-dominio relacionadas
    print(f"\n{'-'*60}")
    print(f"Dependencias inter-dominio que involucran a '{domain}':")
    print(f"{'-'*60}")
    
    interDomainDeps = get_domain_inter_dependencies(db_path, scenario_pk, domain)
    if interDomainDeps:
        for dep in interDomainDeps:
            print(f"  ({dep[9]}){dep[3]} --> ({dep[10]}){dep[4]} ({dep[5]})")
            dep_pk = dep[0]
            if dep_pk not in all_deps_dict:
                all_deps_dict[dep_pk] = dep
    else:
        print(f"  --> No hay dependencias inter-dominio que involucren a {domain}")


def build_MDO_graph(db_path: str, scenario_name: str) -> nx.DiGraph:
    """
    Ejecuta el proceso completo de construcción del grafo MDO.
    Se recorren todos los dominios configurados y se consolidan activos y dependencias.

    Args:
        db_path: Ruta a la base de datos SQLite.
        scenario_name: Nombre del escenario a procesar.

    Returns:
        Grafo global MDO con todos los activos y dependencias del escenario.
    """
    # Se inicializan acumuladores globales para activos y dependencias únicas
    all_assets = []
    all_deps_dict = {}
    
    scenario_pk = get_scenario_pk(db_path, scenario_name)
    
    # Se procesa cada dominio definido en la configuración
    for dominio in DOMINIOS:
        process_and_build_graph_domain(db_path, scenario_pk, dominio, all_assets, all_deps_dict)
    
    # Se convierten las dependencias acumuladas a lista sin duplicados
    all_deps = list(all_deps_dict.values())
    
    # Se construye el grafo global MDO con los datos acumulados
    print(f"\n{'='*60}")    
    print(f"Construcción del grafo global MDO:")
    print(f"{'='*60}")
    
    print(f"Total de dependencias únicas: {len(all_deps)}")
    
    G_global = build_MDO_global_graph(all_assets, all_deps)
    print(f"\nGrafo global MDO construido:")
    print(f"    - Nodos: {G_global.number_of_nodes()}")
    print(f"    - Aristas: {G_global.number_of_edges()}")
    
    return G_global



  
#===============================================[ANALYSIS_FUNCTIONS]===============================================
def get_infected_nodes(graph: nx.DiGraph, compromised_node: str):
    """
    Calcula los nodos afectados por niveles de salto desde un nodo comprometido.
    Se recorren predecesores para identificar activos que dependen directa o indirectamente del nodo inicial.
    
    Args:
        graph: Grafo dirigido que representa activos y dependencias.
        compromised_node: Nodo comprometido inicialmente.

    Returns:
        Tuple con nodos afectados por nivel y aristas afectadas por nivel.
        Devuelve un diccionario vacío si el nodo comprometido no existe.
    """
    # Se inicializan estructuras para recorrer la propagación por niveles
    affected_nodes_by_level = {}
    affected_edges_by_level = {}
    visited_nodes = set()
    current_level_nodes = {compromised_node}
    level = 0
    affected_nodes_by_level[level] = [compromised_node]
    visited_nodes.add(compromised_node)

    # Se verifica que el nodo comprometido exista en el grafo
    try:
        graph.nodes[compromised_node]
    except KeyError:
        print(f"Error: El nodo comprometido '{compromised_node}' no existe en el grafo.")
        return {}

    # Se recorren niveles sucesivos hasta no encontrar nuevos nodos afectados
    while current_level_nodes:
        level += 1
        next_level_nodes = []
        edges_current_level = []
        
        for current_node in current_level_nodes:
            dependent_nodes = list(graph.predecessors(current_node))
           
            for dependent_node in dependent_nodes:
                if dependent_node in visited_nodes:
                    continue
                
                if dependent_node not in next_level_nodes:
                    next_level_nodes.append(dependent_node)
                    visited_nodes.add(dependent_node)

                # Se recuperan los datos de la arista afectada desde NetworkX
                edge_data = graph.get_edge_data(dependent_node, current_node)
                
                edges_current_level.append({
                    'from': dependent_node,
                    'to': current_node,
                    'dependency_type': edge_data['dependency_type'],
                    'weight': edge_data['weight']
                })
        
        
        if next_level_nodes:
            affected_nodes_by_level[level] = next_level_nodes
            affected_edges_by_level[level] = edges_current_level
        
        current_level_nodes = next_level_nodes
    
    return affected_nodes_by_level, affected_edges_by_level


def get_dependency_probs_by_tactic(tactic, affected_edges_by_level):
    """
    Añade probabilidades de propagación a las aristas afectadas según la táctica.
    Se consulta la matriz de dependencias cargada desde configuración.

    Args:
        tactic: Táctica utilizada para consultar la matriz de dependencias.
        affected_edges_by_level: Diccionario de aristas afectadas agrupadas por nivel.

    Returns:
        Diccionario de aristas afectadas con probabilidades añadidas por táctica.
    """
    if tactic not in DEPENDENCY_MATRIX:
        print(f"Error: La táctica '{tactic}' no existe en la matriz de dependencias.")
        return {}
    
    # Se añade la probabilidad correspondiente a cada arista afectada
    for level, edges in affected_edges_by_level.items():
        for edge in edges:
            dep_type = edge['dependency_type']
            if dep_type in DEPENDENCY_MATRIX[tactic]:
                prob = DEPENDENCY_MATRIX[tactic][dep_type]
                edge[f'probability_({tactic})'] = prob
            else:
                edge[f'probability_({tactic})'] = 0.0
    
    return affected_edges_by_level
    

#===============================================[MAIN]===============================================
def main() -> None:
    """
    Punto de entrada principal del programa.

    Args:
        None.

    Returns:
        None. Se muestran escenarios, se construye el grafo global y se ejecuta una prueba básica.
    """
    db_path = str(Path(__file__).parent.parent / "database" / "tfg_catalog.db")

   
    # Se muestran los escenarios disponibles antes de solicitar selección
    scenarios = list_scenarios(db_path)
    print("\nEscenarios disponibles en la BD:")
    print("-" * 80)

    for scenario in scenarios:
        scenario_pk, scenario_name, description, source_file, created_at = scenario
        file_name = Path(source_file).name if source_file else "N/A"
        print(f"[{scenario_pk:>2}] {scenario_name:<15} | file: {file_name:<30} | {created_at}\n")

    scenario_name = input("Ingrese el nombre del escenario: ")

    # Se construye el grafo global del escenario seleccionado
    G_global = build_MDO_graph(db_path, scenario_name)

    # Se ejecuta un bloque de prueba manual sobre un activo concreto
    print("\nEL CODIGO A CONTINUACIÓN ES DE TEST:")
    affected_nodes, affected_edges = get_infected_nodes(G_global, 'asset_002')

    for level, nodes in affected_nodes.items():
        print(f"Nivel {level}: {nodes}")

    for level, edges in affected_edges.items():
        print(f"Nivel {level} - Aristas afectadas: {edges}")

    print(G_global.nodes['asset_002'])

#===============================================[ENTRY_POINT]===============================================
if __name__ == "__main__":
    main()


