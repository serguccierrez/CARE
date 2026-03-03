"""
Este script recoge los datos de la DB creada en create_db.py y los usa para representarlos en un grafo
"""
from pathlib import Path
import sqlite3
import json
import networkx as nx

#===============================================[CONSTANTS]===============================================
def load_constants() -> dict:
    """
    Carga las constantes desde el archivo JSON de configuración.
    """
    config_path = Path(__file__).parent.parent.parent / "Configs" / "constants.json"
    with open(config_path, 'r', encoding='utf-8') as f:
        config = json.load(f)
    return config

def load_dependency_probabilities() -> dict:
    config_path = Path(__file__).parent.parent.parent / "Configs" / "dependency_matrix.json"
    with open(config_path, 'r', encoding='utf-8') as f:
        config = json.load(f)
    return config

# Cargar configuración
_config = load_constants()
DOMINIOS = _config["dominios"]
DEPENDENCIES_TYPES = _config["dependencies_types"]
ASSET_TYPES = _config["asset_types"]
DEPENDENCY_MATRIX = load_dependency_probabilities()


#===============================================[DATABASE_FUNCTIONS]===============================================
def get_domain_assets(db_path: str, domain: str):
    """
    Obtiene y retorna los activos del dominio especificado desde la base de datos SQLite.
    Retorna tuplas: (asset_pk, asset_id, name, asset_type, domain, criticality, cia_c, cia_i, cia_a, operational_state)
    """
    con = sqlite3.connect(db_path)
    try:
        cur = con.cursor()
        cur.execute("SELECT * FROM assets WHERE domain = ?;", (domain,))
        rows = cur.fetchall()
        return rows
    finally:
        con.close()

def get_domain_intra_dependencies(db_path: str, domain: str):
    """
    Obtiene y retorna las dependencias internas del dominio desde la base de datos SQLite.
    Retorna tuplas: (dep_pk, from_asset, to_asset, dependency_type, cia_couple_c, cia_couple_i, cia_couple_a)
    """
    con = sqlite3.connect(db_path)
    try:
        cur = con.cursor()
        cur.execute("""
            SELECT * FROM dependencies
            WHERE from_asset IN (SELECT asset_id FROM assets WHERE domain = ?)
            AND to_asset IN (SELECT asset_id FROM assets WHERE domain = ?);
        """, (domain, domain))
        rows = cur.fetchall()
        return rows
    finally:
        con.close()
        
def get_domain_inter_dependencies(db_path: str, domain: str):
    """
    Obtiene y retorna las dependencias inter-dominio que involucran al dominio especificado.
    Retorna tuplas: (dep_pk, from_asset, to_asset, dependency_type, cia_couple_c, cia_couple_i, cia_couple_a)
    """
    con = sqlite3.connect(db_path)
    try:
        cur = con.cursor()
        cur.execute("""
            SELECT d.*, a1.domain as from_domain, a2.domain as to_domain
            FROM dependencies d
            LEFT JOIN assets a1 ON d.from_asset = a1.asset_id
            LEFT JOIN assets a2 ON d.to_asset = a2.asset_id
            WHERE (d.from_asset IN (SELECT asset_id FROM assets WHERE domain = ?)
            AND d.to_asset NOT IN (SELECT asset_id FROM assets WHERE domain = ?))
            OR (d.to_asset IN (SELECT asset_id FROM assets WHERE domain = ?)
            AND d.from_asset NOT IN (SELECT asset_id FROM assets WHERE domain = ?));
        """, (domain, domain, domain, domain))
        rows = cur.fetchall()
        return rows
    finally:
        con.close()
        
#===============================================[GRAPH_FUNCTIONS]===============================================
def build_intra_domain_graph(domain: str, assets_rows, deps_rows) -> nx.DiGraph:
    """
    Construye y retorna un grafo dirigido de NetworkX para el dominio especificado.
    
    Assets tupla: (asset_pk, asset_id, name, asset_type, domain, criticality, cia_c, cia_i, cia_a, operational_state)
    Deps tupla: (dep_pk, dependency_id, from_asset, to_asset, dependency_type, cia_couple_c, cia_couple_i, cia_couple_a)
    """
    G = nx.DiGraph(domain=domain)

    # Agregar nodos desde tuplas de assets
    for asset in assets_rows:
        asset_pk, asset_id, name, asset_type, dom, criticality, cia_c, cia_i, cia_a, operational_state = asset
        
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
        
    # Agregar aristas desde tuplas de dependencias
    for dep in deps_rows:
        # La BD retorna: (dep_pk, dependency_id, from_asset, to_asset, dependency_type, cia_couple_c, cia_couple_i, cia_couple_a)
        dep_pk, dependency_id, from_asset, to_asset, dependency_type, cia_couple_c, cia_couple_i, cia_couple_a = dep[:8]
        
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
    
    Assets tupla: (asset_pk, asset_id, name, asset_type, domain, criticality, cia_c, cia_i, cia_a, operational_state)
    Deps tupla: (dep_pk, dependency_id, from_asset, to_asset, dependency_type, cia_couple_c, cia_couple_i, cia_couple_a)
    """
    G = nx.DiGraph(domain="MDO Global")

    # Agregar nodos desde tuplas de assets
    for asset in all_assets:
        asset_pk, asset_id, name, asset_type, dom, criticality, cia_c, cia_i, cia_a, operational_state = asset
        
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
        
    # Agregar aristas desde tuplas de dependencias
    for dep in all_deps:
        # Tomar solo los primeros 8 elementos (ignorar los dominios si vienen al final)
        dep_pk, dependency_id, from_asset, to_asset, dependency_type, cia_couple_c, cia_couple_i, cia_couple_a = dep[:8]
        
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
    
    
def process_and_build_graph_domain(db_path: str, domain: str, all_assets: list, all_deps_dict: dict) -> nx.DiGraph:
    """
    Procesa un dominio individual: obtiene activos, dependencias internas e inter-dominio,
    construye el grafo intra-dominio y acumula los datos en las estructuras globales.
    
    Retorna el grafo construido para el dominio especificado.
    """
    # Activos del dominio
    print(f"\n{'='*60}")
    print(f"Activos en el dominio '{domain}':")
    print(f"{'='*60}")
    
    assets = get_domain_assets(db_path, domain)
    
    if assets:
        for asset in assets:
            # asset[1] = asset_id, asset[2] = name
            print(f"  - {asset[1]}: {asset[2]}")
            # Acumular en all_assets
            all_assets.append(asset)
    else:
        print(f"  --> No hay activos en {domain}")
    
    # Dependencias internas del dominio
    print(f"\n{'-'*60}")
    print(f"Dependencias internas en '{domain}':")
    print(f"{'-'*60}")
    
    intraDomainDeps = get_domain_intra_dependencies(db_path, domain)
    
    if intraDomainDeps:
        for dep in intraDomainDeps:
            print(f"  {dep[1]} --> {dep[2]} ({dep[3]})")
            # Acumular en all_deps_dict usando dep_pk como clave
            dep_pk = dep[0]
            if dep_pk not in all_deps_dict:
                all_deps_dict[dep_pk] = dep
    else:
        print(f"  --> No hay dependencias internas en {domain}")
        
    # Construcción del grafo intra-dominio
    G = build_intra_domain_graph(domain, assets, intraDomainDeps)
    print(f"\n✓ Grafo construido para '{domain}':")
    print(f"    - Nodos: {G.number_of_nodes()}")
    print(f"    - Aristas: {G.number_of_edges()}")
    
    # Dependencias inter-dominio del dominio
    print(f"\n{'-'*60}")
    print(f"Dependencias inter-dominio que involucran a '{domain}':")
    print(f"{'-'*60}")
    
    interDomainDeps = get_domain_inter_dependencies(db_path, domain)
    if interDomainDeps:
        for dep in interDomainDeps:
            print(f"  ({dep[7]}){dep[1]} --> ({dep[8]}){dep[2]} ({dep[3]})")
            # Acumular en all_deps_dict usando dep_pk como clave
            dep_pk = dep[0]
            if dep_pk not in all_deps_dict:
                all_deps_dict[dep_pk] = dep
    else:
        print(f"  --> No hay dependencias inter-dominio que involucren a {domain}")


def build_MDO_graph(db_path: str) -> nx.DiGraph:
    """
    Ejecuta el análisis completo del MDO: procesa todos los dominios,
    construye el grafo global y realiza análisis de nodos afectados.
    """
    # Acumuladores globales
    all_assets = []
    all_deps_dict = {}  # Usar dict con dep_pk como clave para evitar duplicados
    
    # Procesar cada dominio
    for dominio in DOMINIOS:
        process_and_build_graph_domain(db_path, dominio, all_assets, all_deps_dict)
    
    # Convertir dict a lista (ya sin duplicados)
    all_deps = list(all_deps_dict.values())
    
    # Construcción del grafo global MDO
    print(f"\n{'='*60}")    
    print(f"Construcción del grafo global MDO:")
    print(f"{'='*60}")
    
    print(f"✓ Total de dependencias únicas: {len(all_deps)}")
    
    G_global = build_MDO_global_graph(all_assets, all_deps)
    print(f"\n✓ Grafo global MDO construido:")
    print(f"    - Nodos: {G_global.number_of_nodes()}")
    print(f"    - Aristas: {G_global.number_of_edges()}")
    
    return G_global



  
#===============================================[ANALYSIS_FUNCTIONS]===============================================
def get_infected_nodes(graph: nx.DiGraph, compromised_node: str):
    """
    Dado un grafo dirigido y un nodo comprometido, retorna una lista de nodos afectados por niveles de salto a través de las dependencias.
    1. Nodos que dependen directamente del nodo comprometido (1 salto).
    2. Nodos que dependen de los nodos afectados en el paso anterior (2 saltos).
    3. Y así sucesivamente hasta que no haya más nodos afectados o se alcance un bucle.
    
    Retorna: Dict[int, List[str]] donde la clave es el nivel de salto y el valor es la lista de nodos afectados en ese nivel.
    """
    #=== Inicialización de variables ===#
    affected_nodes_by_level = {} # Dict[int, List[str]]
    affected_edges_by_level = {} # Dict[int, List[Tuple[str, str]]] (opcional, si queremos también las aristas afectadas)
    visited_nodes = set() # Set[str] de los nodos que ya han sido visitados
    current_level_nodes = {compromised_node} # Nodos del nivel actual que tenemos que procesar( obtener sus dependencias)
    level = 0 # Nivel de salto actual
    affected_nodes_by_level[level] = [compromised_node] # Nivel 0 es el nodo comprometido
    affected_edges_by_level[level] = []    
    visited_nodes.add(compromised_node) # Marcamos el nodo comprometido como visitado

    
    
    #=== Verificación de existencia del nodo comprometido ===#
    try:
        graph.nodes[compromised_node] # Verificamos que el nodo exista en el grafo
    except KeyError:
        print(f"Error: El nodo comprometido '{compromised_node}' no existe en el grafo.")
        return {}
    
    #=== Búsqueda de nodos afectados por niveles de salto ===#
    while current_level_nodes: # Mientras haya nodos en el nivel actual
        level += 1
        next_level_nodes = [] #Nodos a procesar para la siguiente iteración
        edges_current_level = [] # Aristas afectadas en el nivel actual (opcional)
        
        for current_node in current_level_nodes:
            dependent_nodes = list(graph.predecessors(current_node)) # Nodos que dependen del nodo actual
           
            for dependent_node in dependent_nodes:
                if dependent_node in visited_nodes:
                    continue # Ya hemos visitado este nodo, lo saltamos (evitamos bucles)
                
                if dependent_node not in next_level_nodes:
                    next_level_nodes.append(dependent_node) # Añadimos a la lista de nodos para el siguiente nivel
                    visited_nodes.add(dependent_node) # Marcamos el nodo como visitado

                # Obtener datos de la arista directamente con NetworkX
                edge_data = graph.get_edge_data(dependent_node, current_node)
                edges_current_level.append({
                    'from': dependent_node,
                    'to': current_node,
                    'dependency_type': edge_data['dependency_type'],
                    'weight': edge_data['weight']
                })
        
        
        if next_level_nodes: # Si hemos encontrado predecesores del nodo actual, los guardamos en el dict
            affected_nodes_by_level[level] = next_level_nodes
            affected_edges_by_level[level] = edges_current_level
        
        current_level_nodes = next_level_nodes  # Actualizar para la siguiente iteración
    
    return affected_nodes_by_level, affected_edges_by_level


def get_dependency_probs_by_tactic(tactic, affected_edges_by_level):
    if tactic not in DEPENDENCY_MATRIX:
        print(f"Error: La táctica '{tactic}' no existe en la matriz de dependencias.")
        return {}
    
    for level, edges in affected_edges_by_level.items():
        for edge in edges:
            dep_type = edge['dependency_type']
            if dep_type in DEPENDENCY_MATRIX[tactic]:
                prob = DEPENDENCY_MATRIX[tactic][dep_type]
                edge[f'probability_({tactic})'] = prob
            else:
                edge[f'probability_({tactic})'] = 0.0 # Si el tipo de dependencia no está definido para la táctica, asignamos probabilidad 0
    
    return affected_edges_by_level
    

#===============================================[MAIN]===============================================
def main() -> None:
    """
    Punto de entrada principal del programa.
    """
    db_path = str(Path(__file__).parent.parent / "database" / "tfg_catalog_v1.0.0.db")
    G_global = build_MDO_graph(db_path) 
    
      # Test
    print("\nEL CODIGO A CONTINUACIÓN ES DE TEST:")
    affected_nodes, affected_edges = get_infected_nodes(G_global, 'asset_002')
    for level, nodes in affected_nodes.items():
        print(f"Nivel {level}: {nodes}")
    for level, edges in affected_edges.items():
        print(f"Nivel {level} - Aristas afectadas: {edges}")
        
    print(G_global.nodes['asset_002']) # Datos del nodo comprometido
    
   # print(affected_edges[1][0]['dependency_type'])

#===============================================[ENTRY_POINT]===============================================
if __name__ == "__main__":
    main()
