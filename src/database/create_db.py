#!/usr/bin/env python3
"""
Crea una base de datos SQLite para el TFG con tablas:
- scenarios
- assets
- dependencies

Por defecto se crea la BD en el directorio actual (working directory).

Uso:
  python create_db.py
  python create_db.py --recreate
  python create_db.py --db otra_ruta.db --recreate
"""

#===============================================[IMPORTS]===============================================
import argparse
import sqlite3
from pathlib import Path

#===============================================[DATABASE_SCHEMA]===============================================

# Definición del esquema de la base de datos en lenguaje SQL
DataDefinitionLanguage = """
PRAGMA foreign_keys = ON;

-- ===============================================
-- Tabla de escenarios
-- ===============================================
CREATE TABLE IF NOT EXISTS scenarios (
  scenario_pk      INTEGER PRIMARY KEY AUTOINCREMENT,
  scenario_name    TEXT NOT NULL UNIQUE,
  description      TEXT,
  source_file      TEXT,
  created_at       TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- ===============================================
-- Tabla de activos (nodos)
-- ===============================================
CREATE TABLE IF NOT EXISTS assets (
  asset_pk           INTEGER PRIMARY KEY AUTOINCREMENT,
  scenario_fk        INTEGER NOT NULL,
  asset_id           TEXT NOT NULL,
  name               TEXT NOT NULL,
  asset_type         TEXT NOT NULL,
  domain             TEXT NOT NULL,
  criticality        REAL NOT NULL CHECK (criticality >= 0 AND criticality <= 1),
  cia_c              REAL NOT NULL CHECK (cia_c >= 0 AND cia_c <= 1),
  cia_i              REAL NOT NULL CHECK (cia_i >= 0 AND cia_i <= 1),
  cia_a              REAL NOT NULL CHECK (cia_a >= 0 AND cia_a <= 1),
  operational_state  TEXT NOT NULL,

  FOREIGN KEY (scenario_fk) REFERENCES scenarios(scenario_pk) ON DELETE CASCADE,
  UNIQUE (scenario_fk, asset_id),
  CHECK (abs((cia_c + cia_i + cia_a) - 1.0) <= 0.01)
);

-- ===============================================
-- Tabla de dependencias (aristas)
-- ===============================================
CREATE TABLE IF NOT EXISTS dependencies (
  dep_pk            INTEGER PRIMARY KEY AUTOINCREMENT,
  scenario_fk       INTEGER NOT NULL,
  dependency_id     TEXT NOT NULL,
  from_asset        TEXT NOT NULL,
  to_asset          TEXT NOT NULL,
  dependency_type   TEXT NOT NULL,
  cia_couple_c      REAL NOT NULL CHECK (cia_couple_c >= 0 AND cia_couple_c <= 1),
  cia_couple_i      REAL NOT NULL CHECK (cia_couple_i >= 0 AND cia_couple_i <= 1),
  cia_couple_a      REAL NOT NULL CHECK (cia_couple_a >= 0 AND cia_couple_a <= 1),

  FOREIGN KEY (scenario_fk) REFERENCES scenarios(scenario_pk) ON DELETE CASCADE,
  FOREIGN KEY (scenario_fk, from_asset) REFERENCES assets(scenario_fk, asset_id) ON DELETE CASCADE,
  FOREIGN KEY (scenario_fk, to_asset)   REFERENCES assets(scenario_fk, asset_id) ON DELETE CASCADE,

  UNIQUE (scenario_fk, dependency_id),
  UNIQUE (scenario_fk, from_asset, to_asset, dependency_type),
  CHECK (from_asset <> to_asset)
);

-- ===============================================
-- Índices
-- ===============================================
CREATE INDEX IF NOT EXISTS idx_assets_scenario_fk
  ON assets(scenario_fk);

CREATE INDEX IF NOT EXISTS idx_deps_scenario_fk
  ON dependencies(scenario_fk);

CREATE INDEX IF NOT EXISTS idx_deps_from_asset
  ON dependencies(scenario_fk, from_asset);

CREATE INDEX IF NOT EXISTS idx_deps_to_asset
  ON dependencies(scenario_fk, to_asset);
"""

#===============================================[FUNCTIONS]===============================================
def create_db(db_path: Path, recreate: bool) -> None:
    """
    Crea (o recrea) una base de datos SQLite con el esquema definido en DataDefinitionLanguage.
    - db_path: ruta del fichero .db
    - recreate: si True, borra el fichero si existe y lo crea desde cero
    """
    # Crea el directorio si no existe
    db_path.parent.mkdir(parents=True, exist_ok=True)
    
    if recreate and db_path.exists():
        db_path.unlink()

    # Se intenta conectar con la base de datos (si no existe, SQLite crea el fichero automáticamente)
    con = sqlite3.connect(str(db_path))
    try:
        # En SQLite, las FKs se activan por conexión
        con.execute("PRAGMA foreign_keys = ON;")

        # Ejecuta todas las sentencias del DataDefinitionLanguage (múltiples CREATE TABLE/INDEX)
        con.executescript(DataDefinitionLanguage)

        con.commit()
    finally:
        con.close()


#===============================================[MAIN]===============================================
def main() -> None:
    parser = argparse.ArgumentParser(description="Crea la BD SQLite (assets + dependencies).")

    # Por defecto: BD en el directorio src/database
    default_db = Path(__file__).parent / "tfg_catalog.db"

    parser.add_argument(
        "--db",
        default=str(default_db),
        help=f"Ruta del fichero .db (por defecto: {default_db})",
    )
    parser.add_argument(
        "--recreate",
        action="store_true",
        help="Borra y recrea la BD si ya existe",
    )

    args = parser.parse_args()
    create_db(Path(args.db), recreate=args.recreate)
    print(f"OK: BD creada en {args.db}")

#===============================================[ENTRY_POINT]===============================================
if __name__ == "__main__":
    main()
