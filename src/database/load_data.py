"""
Se cargan datos desde un archivo Excel y se insertan en una base de datos SQLite.
Se procesan activos, dependencias y escenarios para dejar listo el análisis posterior.
"""

#===============================================[IMPORTS]===============================================
import pandas as pd
import sqlite3
from pathlib import Path


#===============================================[CONSTANTS]===============================================
DB_PATH = Path(__file__).parent.parent / "database" / "tfg_catalog.db"

#===============================================[DATA_LOADING]===============================================
def load_data_from_excel(excel_path: Path) -> tuple[pd.DataFrame, pd.DataFrame]:
    """
    Carga datos desde un archivo Excel con hojas de activos y dependencias.
    Se obtienen copias independientes de las hojas necesarias para el procesamiento.
   
    Args:
        excel_path: Ruta del archivo Excel desde el que se cargan los datos.

    Returns:
        Tuple con dos DataFrames: activos y dependencias.
    """

    dfs = pd.read_excel(excel_path, sheet_name=None) # Se cargan todas las hojas en un diccionario {nombre_hoja: DataFrame}
    
    # Se obtienen las hojas "Assets" y "Dependencies" para su tratamiento posterior
    assets_df = dfs["Assets"].copy()
    deps_df = dfs["Dependencies"].copy()
    return assets_df, deps_df


#===============================================[SCENARIO_CREATION]===============================================
def create_scenario(con, scenario_name: str, description: str = None, source_file: str = None) -> int:
    """
    Crea un nuevo escenario usando una conexión abierta con la base de datos.
    Se devuelve la clave primaria generada para asociar activos y dependencias.

    Args:
        con: Conexión SQLite abierta sobre la base de datos destino.
        scenario_name: Nombre del escenario que se va a crear.
        description: Descripción opcional del escenario.
        source_file: Ruta del archivo fuente desde el que se han cargado los datos.

    Returns:
        Clave primaria del escenario recién creado.
    """
    cur = con.cursor()

    # Se inserta un nuevo escenario y se obtiene su clave primaria
    cur.execute("""
        INSERT INTO scenarios (scenario_name, description, source_file)
        VALUES (?, ?, ?)
    """, (scenario_name, description, source_file))

    return cur.lastrowid


def create_empty_scenario(db_path: Path, scenario_name: str, description: str = None, source_file: str = None) -> int:
    """
    Crea un escenario vacío y confirma la inserción en la base de datos.
    Se permite registrar un escenario sin cargar todavía activos ni dependencias.

    Args:
        db_path: Ruta del fichero .db donde se registra el escenario.
        scenario_name: Nombre del escenario que se va a crear.
        description: Descripción opcional del escenario.
        source_file: Ruta del archivo fuente desde el que se han cargado los datos.

    Returns:
        Clave primaria del escenario recién creado.
    """
    # Se abre una conexión directa con la base de datos indicada
    con = sqlite3.connect(db_path)

    try:
        # Se crea el escenario y se confirma la transacción
        scenario_pk = create_scenario(con, scenario_name, description, source_file)
        con.commit()
        return scenario_pk
    finally:
        # Se cierra la conexión con la base de datos
        con.close()




#===============================================[COLUMN_MAPPING]===============================================
def map_columns(assets_df: pd.DataFrame, deps_df: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame]:
    """
    Mapea columnas de Excel a los nombres esperados por SQLite.
    Se normalizan alias habituales para activos y dependencias.

    Args:
        assets_df: DataFrame con datos de activos cargados desde Excel.
        deps_df: DataFrame con datos de dependencias cargados desde Excel.

    Returns:
        Tuple con DataFrames renombrados para activos y dependencias.
    """
    # Se renombran posibles alias de identificador de activo
    assets_df = assets_df.rename(columns={
        "asset_id": "asset_id",
        "key": "asset_id",
        "id": "asset_id",
    })

    # Se renombran posibles alias de origen y destino de dependencias
    deps_df = deps_df.rename(columns={
        "from_asset_id": "from_asset",
        "to_asset_id": "to_asset",
        "from": "from_asset",
        "to": "to_asset",
    })
    
    return assets_df, deps_df

#===============================================[COLUMN_SELECTION]===============================================
def select_required_columns(assets_df: pd.DataFrame, deps_df: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame]:
    """
    Selecciona de cada DataFrame solo las columnas necesarias para la inserción en la base de datos.
    Se descartan columnas auxiliares que no forman parte del esquema persistido.

    Args:
        assets_df: DataFrame con datos de activos cargados desde Excel.
        deps_df: DataFrame con datos de dependencias cargados desde Excel.

    Returns:
        Tuple con DataFrames filtrados para activos y dependencias.
    """
    # Se seleccionan las columnas requeridas para la tabla assets
    assets_df = assets_df[[
        "asset_id",
        "name",
        "asset_type",
        "domain",
        "criticality",
        "cia_c",
        "cia_i",
        "cia_a",
        "operational_state",
    ]].copy()

    # Se seleccionan las columnas requeridas para la tabla dependencies
    deps_df = deps_df[[
        "dependency_id",
        "from_asset",
        "to_asset",
        "dependency_type",
        "cia_couple_c",
        "cia_couple_i",
        "cia_couple_a",
    ]].copy()
    
    return assets_df, deps_df

#===============================================[DATA_CLEANING]===============================================
def clean_data(assets_df: pd.DataFrame, deps_df: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame]:
    """
    Limpia datos textuales y asegura que las columnas clave sean cadenas.
    Se eliminan espacios extra en activos y dependencias.

    Args:
        assets_df: DataFrame con datos de activos cargados desde Excel.
        deps_df: DataFrame con datos de dependencias cargados desde Excel.

    Returns:
        Tuple con DataFrames limpios para activos y dependencias.
    """
    # Se normalizan las columnas textuales de activos
    for col in ["asset_id", "name", "asset_type", "domain", "operational_state"]:
        assets_df[col] = assets_df[col].astype(str).str.strip()

    # Se normalizan las columnas textuales de dependencias
    for col in ["from_asset", "to_asset", "dependency_type"]:
        deps_df[col] = deps_df[col].astype(str).str.strip()
    
    return assets_df, deps_df

#===============================================[VALIDATION]===============================================
def validate_data(assets_df: pd.DataFrame, deps_df: pd.DataFrame) -> None:
    """
    Valida integridad de datos antes de cargar en BD.
    Se lanzan excepciones si se detectan problemas.

    Args:
        assets_df: DataFrame con datos de activos cargados desde Excel.
        deps_df: DataFrame con datos de dependencias cargados desde Excel.

    Returns:
        None. Lanza ValueError si hay problemas de validación.
    """

    
    # Se comprueba que no existan activos con el mismo asset_id
    if assets_df["asset_id"].duplicated().any():
        dup = assets_df.loc[assets_df["asset_id"].duplicated(), "asset_id"].unique().tolist()
        raise ValueError(f"asset_id duplicado(s): {dup}")

    # Se comprueba que la suma de los pesos CIA de cada activo sea aproximadamente 1
    s = pd.to_numeric(assets_df["cia_c"]) + pd.to_numeric(assets_df["cia_i"]) + pd.to_numeric(assets_df["cia_a"])
    bad = assets_df.loc[(s - 1.0).abs() > 0.01, ["asset_id", "cia_c", "cia_i", "cia_a"]]
    if not bad.empty:
        raise ValueError("Hay activos cuya suma CIA no es ~1:\n" + bad.to_string(index=False))

    # Se comprueba que las dependencias apunten a activos existentes
    keys = set(assets_df["asset_id"].tolist())
    missing_from = sorted(set(deps_df["from_asset"]) - keys)
    missing_to = sorted(set(deps_df["to_asset"]) - keys)
    if missing_from or missing_to:
        raise ValueError(
            "Dependencias apuntan a activos inexistentes.\n"
            f"from_asset no encontrados: {missing_from}\n"
            f"to_asset no encontrados: {missing_to}"
        )

#===============================================[DATABASE_INSERTION]===============================================
def insert_into_database(assets_df: pd.DataFrame, deps_df: pd.DataFrame, db_path: Path, scenario_name: str, description: str = None, source_file: str = None ) -> None:
    """
    Inserta un nuevo escenario en la base de datos junto con sus activos y dependencias.
    Se activa la integridad referencial y se confirma la carga completa en una transacción.

    Args:
        assets_df: DataFrame con datos de activos limpios y validados.
        deps_df: DataFrame con datos de dependencias limpios y validados.
        db_path: Ruta del fichero .db donde se insertan los datos.
        scenario_name: Nombre del escenario que se va a crear.
        description: Descripción opcional del escenario.
        source_file: Ruta del archivo fuente desde el que se han cargado los datos.

    Returns:
        None. Lanza excepciones si hay problemas de inserción.
    """
    # Se abre una conexión con la base de datos destino
    con = sqlite3.connect(db_path)

    try:
        # Se activan las claves foráneas para la conexión actual
        con.execute("PRAGMA foreign_keys = ON;")
        cur = con.cursor()

        # Se crea un nuevo escenario y se obtiene su clave primaria
        scenario_pk = create_scenario(con, scenario_name, description, source_file)

        # Se preparan copias de los DataFrames para asociarlas al escenario
        assets_df = assets_df.copy()
        deps_df = deps_df.copy()

        # Se añade la clave foránea del escenario a activos y dependencias
        assets_df["scenario_fk"] = scenario_pk
        deps_df["scenario_fk"] = scenario_pk

        # Se insertan los activos en la tabla assets
        assets_df.to_sql("assets", con, if_exists="append", index=False)

        # Se insertan las dependencias en la tabla dependencies
        deps_df.to_sql("dependencies", con, if_exists="append", index=False)

        # Se confirma la transacción de inserción
        con.commit()

        # Se muestra un resumen de la carga realizada
        print(f" Escenario '{scenario_name}' creado correctamente")
        print(f"  - scenario_pk: {scenario_pk}")
        print(f"  - Activos: {len(assets_df)}")
        print(f"  - Dependencias: {len(deps_df)}")

    finally:
        # Se cierra la conexión con la base de datos
        con.close()

#===============================================[DATA_ORCHESTRATION]===============================================
def load_and_insert_data(excel_path: Path, db_path: Path, scenario_name: str, description: str = None) -> None:
    """
    Orquesta el flujo completo de carga, limpieza, validación e inserción.
    Se usa como función principal para poblar la base de datos desde otros módulos.

    Args:
        excel_path: Ruta del archivo Excel que se va a cargar.
        db_path: Ruta del fichero .db donde se insertan los datos.
        scenario_name: Nombre del escenario que se va a crear.
        description: Descripción opcional del escenario.

    Returns:
        None. Lanza excepciones si hay problemas en cualquier paso del proceso.
    """
    # Se cargan datos desde Excel
    assets_df, deps_df = load_data_from_excel(excel_path)
    
    # Se seleccionan las columnas necesarias
    assets_df, deps_df = select_required_columns(assets_df, deps_df)
    
    # Se limpian los datos cargados
    assets_df, deps_df = clean_data(assets_df, deps_df)
    
    # Se validan los datos antes de la inserción
    validate_data(assets_df, deps_df)
    
    # Se insertan los datos en la base de datos
    insert_into_database(assets_df, deps_df, db_path, scenario_name, description, source_file=str(excel_path))
    
    # Se muestra un resumen final del proceso de carga
    print(f" Datos cargados exitosamente en {db_path}")
    print(f"  - Activos: {len(assets_df)}")
    print(f"  - Dependencias: {len(deps_df)}")

