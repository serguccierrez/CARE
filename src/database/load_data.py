#===============================================[IMPORTS]===============================================
import pandas as pd
import sqlite3
from pathlib import Path

#===============================================[DATA_LOADING]===============================================
def load_data_from_excel(excel_path: Path) -> tuple[pd.DataFrame, pd.DataFrame]:
    """
    Carga datos desde archivo Excel.
    Retorna tupla (assets_df, deps_df)
    """
    dfs = pd.read_excel(excel_path, sheet_name=None)
    assets_df = dfs["Assets"].copy()
    deps_df = dfs["Dependencies"].copy()
    return assets_df, deps_df


#==============================================[CREATE_SCENARIO]===============================================
def create_scenario(con, scenario_name: str, description: str = None, source_file: str = None) -> int:
    """
    Crea un nuevo escenario y devuelve su scenario_pk.
    """
    cur = con.cursor()

    cur.execute("""
        INSERT INTO scenarios (scenario_name, description, source_file)
        VALUES (?, ?, ?)
    """, (scenario_name, description, source_file))

    return cur.lastrowid




#===============================================[COLUMN_MAPPING]===============================================
def map_columns(assets_df: pd.DataFrame, deps_df: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame]:
    """
    Mapea columnas de Excel a nombres esperados por SQLite.
    """
    assets_df = assets_df.rename(columns={
        "asset_id": "asset_id",
        "key": "asset_id",
        "id": "asset_id",
    })

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
    Selecciona solo las columnas requeridas por SQLite.
    """
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
    Limpia datos (elimina espacios extra).
    """
    for col in ["asset_id", "name", "asset_type", "domain", "operational_state"]:
        assets_df[col] = assets_df[col].astype(str).str.strip()

    for col in ["from_asset", "to_asset", "dependency_type"]:
        deps_df[col] = deps_df[col].astype(str).str.strip()
    
    return assets_df, deps_df

#===============================================[VALIDATION]===============================================
def validate_data(assets_df: pd.DataFrame, deps_df: pd.DataFrame) -> None:
    """
    Valida integridad de datos antes de cargar en BD.
    Lanza excepciones si hay problemas.
    """
    if assets_df["asset_id"].duplicated().any():
        dup = assets_df.loc[assets_df["asset_id"].duplicated(), "asset_id"].unique().tolist()
        raise ValueError(f"asset_id duplicado(s): {dup}")

    s = pd.to_numeric(assets_df["cia_c"]) + pd.to_numeric(assets_df["cia_i"]) + pd.to_numeric(assets_df["cia_a"])
    bad = assets_df.loc[(s - 1.0).abs() > 0.01, ["asset_id", "cia_c", "cia_i", "cia_a"]]
    if not bad.empty:
        raise ValueError("Hay activos cuya suma CIA no es ~1:\n" + bad.to_string(index=False))

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
    """
    con = sqlite3.connect(db_path)

    try:
        con.execute("PRAGMA foreign_keys = ON;")
        cur = con.cursor()

        # Creamos nuevo escenario y obtenemos su PK para asociarla luego a activos y dependencias
        scenario_pk = create_scenario(con, scenario_name, description, source_file)

        # Hacemos esa asociación añadiendo la columna scenario_fk a ambos DataFrames
        assets_df = assets_df.copy()
        deps_df = deps_df.copy()

        assets_df["scenario_fk"] = scenario_pk
        deps_df["scenario_fk"] = scenario_pk

        # Insertamos los acrivos en la tabla assets
        assets_df.to_sql("assets", con, if_exists="append", index=False)

        # Insertamos las dependencias en la tabla dependencies
        deps_df.to_sql("dependencies", con, if_exists="append", index=False)

        con.commit()

        print(f" Escenario '{scenario_name}' creado correctamente")
        print(f"  - scenario_pk: {scenario_pk}")
        print(f"  - Activos: {len(assets_df)}")
        print(f"  - Dependencias: {len(deps_df)}")

    finally:
        con.close()

#===============================================[MAIN_LOAD_DATA]===============================================
def load_and_insert_data(excel_path: Path, db_path: Path, scenario_name: str, description: str = None) -> None:
    """
    Orquesta el flujo completo: carga, mapeo, limpieza, validación e inserción.
    Función principal para ser llamada desde otro módulo.
    """
    # Cargamos datos desde Excel
    assets_df, deps_df = load_data_from_excel(excel_path)
    
    # Seleccionamos columnas necesarias
    assets_df, deps_df = select_required_columns(assets_df, deps_df)
    
    # Limpiamos datos
    assets_df, deps_df = clean_data(assets_df, deps_df)
    
    # Validamos datos
    validate_data(assets_df, deps_df)
    
    # Insertamos datos en BD
    insert_into_database(assets_df, deps_df, db_path, scenario_name, description, source_file=str(excel_path))
    
    print(f"✓ Datos cargados exitosamente en {db_path}")
    print(f"  - Activos: {len(assets_df)}")
    print(f"  - Dependencias: {len(deps_df)}")

