# CARE - Cyber Action Recommendation Engine

> **ES**: Sistema de apoyo a la decision para analizar incidentes de ciberseguridad, estimar riesgo residual y recomendar contramedidas trazables bajo restricciones operativas.  
> **EN**: Decision-support system for cybersecurity incident analysis, residual risk estimation, and traceable countermeasure recommendation under operational constraints.

CARE is an academic engineering project developed as a **Final Degree Project**. It transforms a structured threat scenario into an explainable recommendation process by combining asset modeling, dependency graphs, MITRE ATT&CK knowledge, probabilistic inference, CIA risk assessment, and constrained optimization.

CARE es un proyecto academico de ingenieria desarrollado como **Trabajo de Fin de Grado**. Convierte un escenario de amenaza estructurado en un proceso de recomendacion explicable mediante modelado de activos, grafos de dependencias, conocimiento MITRE ATT&CK, inferencia probabilistica, evaluacion de riesgo CIA y optimizacion con restricciones.

The system is not intended to automate incident response or replace expert judgment. Its purpose is to provide a quantitative, reproducible, and transparent basis for comparing mitigation alternatives.

El sistema no pretende automatizar la respuesta ante incidentes ni sustituir el criterio experto. Su objetivo es proporcionar una base cuantitativa, reproducible y transparente para comparar alternativas de mitigacion.

---

## Table of Contents

- [Overview / Resumen](#overview--resumen)
- [Key Features / Caracteristicas Principales](#key-features--caracteristicas-principales)
- [Architecture / Arquitectura](#architecture--arquitectura)
- [Workflow / Flujo de Trabajo](#workflow--flujo-de-trabajo)
- [Screenshots / Capturas](#screenshots--capturas)
- [Installation / Instalacion](#installation--instalacion)
- [Quick Start / Uso Rapido](#quick-start--uso-rapido)
- [CLI Reference / Referencia CLI](#cli-reference--referencia-cli)
- [Generated Artifacts / Artefactos Generados](#generated-artifacts--artefactos-generados)
- [Data and Configuration / Datos y Configuracion](#data-and-configuration--datos-y-configuracion)
- [Technology Stack / Tecnologias](#technology-stack--tecnologias)
- [Design Principles / Criterios de Diseno](#design-principles--criterios-de-diseno)
- [Academic Scope / Alcance Academico](#academic-scope--alcance-academico)
- [Limitations / Limitaciones](#limitations--limitaciones)

---

## Overview / Resumen

**EN**

Real-world digital systems are composed of assets that depend on each other. When a threat affects one component, the impact may propagate through those dependencies, affect different risk dimensions, and lead to mitigation decisions with different costs, deployment times, and expected effects.

CARE addresses this problem through an end-to-end analytical workflow:

1. Load asset and dependency scenarios from a structured catalog.
2. Represent the system as a directed dependency graph.
3. Associate MITRE ATT&CK techniques with specific assets.
4. Propagate potential impact through the graph.
5. Estimate residual risk across Confidentiality, Integrity, and Availability.
6. Generate mitigation scenarios for affected assets.
7. Select countermeasures through optimization under budget and time constraints.
8. Export results as JSON artifacts, CLI dashboards, persisted runs, and Markdown reports.

**ES**

Los sistemas digitales reales estan formados por activos interdependientes. Cuando una amenaza afecta a un componente, el impacto puede propagarse a traves de esas dependencias, alterar distintas dimensiones de riesgo y generar decisiones de mitigacion con costes, tiempos de despliegue y efectos esperados diferentes.

CARE aborda este problema mediante un flujo analitico completo:

1. Carga escenarios de activos y dependencias desde un catalogo estructurado.
2. Representa el sistema como un grafo dirigido de dependencias.
3. Asocia tecnicas MITRE ATT&CK a activos concretos.
4. Propaga el impacto potencial a traves del grafo.
5. Estima riesgo residual en Confidencialidad, Integridad y Disponibilidad.
6. Genera escenarios de mitigacion para los activos afectados.
7. Selecciona contramedidas mediante optimizacion bajo restricciones de presupuesto y tiempo.
8. Exporta resultados como artefactos JSON, dashboards CLI, runs persistidas e informes Markdown.

---

## Key Features / Caracteristicas Principales

| EN | ES |
| --- | --- |
| Scenario management for assets and dependencies. | Gestion de escenarios con activos y dependencias. |
| Directed graph representation of infrastructure relationships. | Representacion mediante grafo dirigido de relaciones entre componentes. |
| Local MITRE ATT&CK knowledge integration. | Integracion local de conocimiento MITRE ATT&CK. |
| Random and controlled threat simulation modes. | Modos de simulacion aleatoria y controlada. |
| Impact propagation across dependency levels. | Propagacion de impacto por niveles de dependencia. |
| Bayesian inference for residual risk estimation. | Inferencia bayesiana para estimar riesgo residual. |
| CIA-based risk assessment. | Evaluacion de riesgo basada en CIA. |
| Countermeasure optimization under cost and time constraints. | Optimizacion de contramedidas bajo restricciones de coste y tiempo. |
| Rich-based CLI with panels, tables, dashboards, and reports. | CLI basada en Rich con paneles, tablas, dashboards y reportes. |
| Persisted analysis runs with Markdown report generation. | Runs persistidas con generacion de informes Markdown. |

---

## Architecture / Arquitectura

```text
TFG_motor-contramedidas-ciberneticas/
|-- configs/                    # CPDs, MITRE mappings, countermeasure catalog
|-- data/                       # Input data and local MITRE ATT&CK dataset
|-- images/                     # Screenshots used in this README
|-- src/
|   |-- cli/                    # CARE CLI: init, db, attack, dashboard, optimize, reports
|   |-- cyberrecom/             # Analytical workflow orchestration
|   |-- database/               # SQLite persistence and scenario loading
|   |-- graph/                  # Graph construction and dependency analysis
|   |-- reporting/              # Report and solution export
|   |-- risk/                   # Risk models, inference, and optimization
|-- README.md
```

**EN**

The repository separates user interaction, data persistence, graph analysis, risk modeling, and recommendation logic. This structure makes the analytical process easier to inspect and supports traceability from input data to final recommendations.

**ES**

El repositorio separa la interaccion con el usuario, la persistencia de datos, el analisis del grafo, el modelado de riesgo y la logica de recomendacion. Esta estructura facilita la inspeccion del proceso analitico y mantiene la trazabilidad desde los datos de entrada hasta las recomendaciones finales.

---

## Workflow / Flujo de Trabajo

### 1. Scenario / Escenario

**EN**: CARE starts from a scenario containing assets and dependencies. Each asset includes attributes such as criticality, type, domain, operational state, and CIA weights.  
**ES**: CARE parte de un escenario compuesto por activos y dependencias. Cada activo incluye atributos como criticidad, tipo, dominio, estado operativo y pesos CIA.

### 2. Incident / Incidente

**EN**: The user can run a random simulation or define a controlled injection with an affected asset, a MITRE ATT&CK technique, and a confidence level.  
**ES**: El usuario puede ejecutar una simulacion aleatoria o definir una inyeccion controlada indicando activo afectado, tecnica MITRE ATT&CK y nivel de confianza.

### 3. Propagation / Propagacion

**EN**: Starting from the initial asset, CARE analyzes the graph and determines which nodes and dependencies may be affected.  
**ES**: A partir del activo inicial, CARE analiza el grafo y determina que nodos y dependencias pueden verse afectados.

### 4. Risk / Riesgo

**EN**: The engine builds and solves probabilistic models to estimate residual risk across Confidentiality, Integrity, and Availability. Results are aggregated by incident, asset, and system.  
**ES**: El motor construye y resuelve modelos probabilisticos para estimar riesgo residual en Confidencialidad, Integridad y Disponibilidad. Los resultados se agregan por incidente, activo y sistema.

### 5. Decision / Decision

**EN**: For each affected asset, CARE generates mitigation alternatives. Each alternative combines a countermeasure, cost, deployment time, and estimated risk effect.  
**ES**: Para cada activo afectado, CARE genera alternativas de mitigacion. Cada alternativa combina una contramedida, coste, tiempo de despliegue y efecto estimado sobre el riesgo.

### 6. Optimization / Optimizacion

**EN**: The final recommendation is formulated as a binary linear optimization problem. The system selects the alternative that minimizes the chosen objective while respecting configured constraints.  
**ES**: La recomendacion final se formula como un problema de optimizacion lineal binaria. El sistema selecciona la alternativa que minimiza el objetivo elegido respetando las restricciones configuradas.

Supported objectives / Objetivos soportados:

- Global risk / Riesgo global
- Confidentiality / Confidencialidad
- Integrity / Integridad
- Availability / Disponibilidad

### 7. Reporting / Reporte

**EN**: Each execution can be stored as a persisted run. When saving a run, CARE generates a Markdown report with the main execution data and available results.  
**ES**: Cada ejecucion puede guardarse como una run persistida. Al guardar una run, CARE genera un informe Markdown con la informacion principal de la ejecucion y los resultados disponibles.

---

## Screenshots / Capturas

### System initialization / Inicializacion del sistema

![CARE init](./images/init.png)

### Scenario management / Gestion de escenarios

![CARE database](./images/db.png)

### Threat injection / Inyeccion de amenazas

![CARE attack](./images/attack.png)

### Risk dashboard / Dashboard de riesgo

![CARE dashboard](./images/dashboard.png)

### Countermeasure optimization / Optimizacion de contramedidas

![CARE optimization](./images/optimize.png)

### Runs and reports / Runs y reportes

![CARE reports](./images/reports.png)

### Generated Markdown report / Informe Markdown generado

![CARE markdown report](./images/report-markdown.png)

---

## Installation / Instalacion

**EN**

Recommended requirements:

- Python 3.10 or higher.
- Dedicated virtual environment.
- Dependencies installed from `configs/requirements.txt`.

**ES**

Requisitos recomendados:

- Python 3.10 o superior.
- Entorno virtual dedicado.
- Dependencias instaladas desde `configs/requirements.txt`.

From the repository root / Desde la raiz del repositorio:

```bash
python -m venv .venv
.\.venv\Scripts\activate
pip install -r configs/requirements.txt
```

---

## Quick Start / Uso Rapido

Initialize the CLI / Inicializar la CLI:

```bash
python -m src.cli.care init
```

Load an existing scenario / Cargar un escenario existente:

```bash
python -m src.cli.care db load --scenario "<scenario_name>"
```

Create a scenario from Excel / Crear un escenario desde Excel:

```bash
python -m src.cli.care db create --scenario "<scenario_name>" --description "<description>" --source "<excel_path>"
```

Run a random simulation / Ejecutar una simulacion aleatoria:

```bash
python -m src.cli.care attack run --random
```

Configure and run a controlled simulation / Configurar y ejecutar una simulacion controlada:

```bash
python -m src.cli.care attack select --asset "<asset_id>" --ttp "T1190" --confidence 0.75
python -m src.cli.care attack run
```

Open the dashboard / Abrir el dashboard:

```bash
python -m src.cli.care dashboard
```

Configure and run optimization / Configurar y ejecutar la optimizacion:

```bash
python -m src.cli.care optimize config --objective global --budget 50000 --time 210
python -m src.cli.care optimize run
```

Save a run and generate its Markdown report / Guardar una run y generar su informe Markdown:

```bash
python -m src.cli.care reports save --filename "<report_name.md>" --description "<description>"
```

List stored runs / Listar runs guardadas:

```bash
python -m src.cli.care reports
python -m src.cli.care reports --scenario "<scenario_name>"
```

Restore a previous run / Cargar una run previa:

```bash
python -m src.cli.care reports load --run_name "<run_name>"
```

---

## CLI Reference / Referencia CLI

```text
python -m src.cli.care init
python -m src.cli.care db
python -m src.cli.care attack
python -m src.cli.care dashboard
python -m src.cli.care optimize
python -m src.cli.care reports
```

| Command | Purpose |
| --- | --- |
| `init` | Initializes the CLI context and renders the main screen. |
| `db` | Manages scenarios, assets, and dependencies. |
| `attack` | Configures and executes threat simulations. |
| `dashboard` | Displays the risk state of the latest execution. |
| `optimize` | Configures constraints and runs countermeasure selection. |
| `reports` | Lists, saves, and restores analysis runs. |

| Comando | Proposito |
| --- | --- |
| `init` | Inicializa el contexto de la CLI y muestra la pantalla principal. |
| `db` | Gestiona escenarios, activos y dependencias. |
| `attack` | Configura y ejecuta simulaciones de amenaza. |
| `dashboard` | Visualiza el estado de riesgo de la ultima ejecucion. |
| `optimize` | Configura restricciones y ejecuta la seleccion de contramedidas. |
| `reports` | Lista, guarda y restaura runs de analisis. |

---

## Generated Artifacts / Artefactos Generados

| Path | Content |
| --- | --- |
| `src/cli/context.json` | Operational state of the CLI session. |
| `configs/bn_CPDs.json` | Dynamic CPDs used by the Bayesian network. |
| `src/reporting/report.json` | Structured risk analysis report. |
| `src/reporting/optimization_solution.json` | Optimization solution and selected countermeasures. |
| `src/reporting/<run_name>.md` | Narrative Markdown report generated when saving a run. |
| `src/database/tfg_catalog.db` | SQLite database with scenarios, assets, dependencies, and runs. |

| Ruta | Contenido |
| --- | --- |
| `src/cli/context.json` | Estado operativo de la sesion CLI. |
| `configs/bn_CPDs.json` | CPDs dinamicas utilizadas por la red bayesiana. |
| `src/reporting/report.json` | Reporte estructurado del analisis de riesgo. |
| `src/reporting/optimization_solution.json` | Solucion de optimizacion y contramedidas seleccionadas. |
| `src/reporting/<run_name>.md` | Informe narrativo Markdown generado al guardar una run. |
| `src/database/tfg_catalog.db` | Base de datos SQLite con escenarios, activos, dependencias y runs. |

---

## Data and Configuration / Datos y Configuracion

| File | Description |
| --- | --- |
| `data/enterprise-attack.json` | Local MITRE ATT&CK Enterprise dataset. |
| `configs/countermeasures.json` | Countermeasure catalog with cost, time, and expected effect. |
| `configs/ttps_to_mitigations.json` | Mapping between MITRE techniques and candidate mitigations. |
| `configs/bn_CPDs_template.json` | Base probabilistic CPD template. |
| `configs/requirements.txt` | Python dependencies. |

| Fichero | Descripcion |
| --- | --- |
| `data/enterprise-attack.json` | Dataset local de MITRE ATT&CK Enterprise. |
| `configs/countermeasures.json` | Catalogo de contramedidas con coste, tiempo y efecto esperado. |
| `configs/ttps_to_mitigations.json` | Relacion entre tecnicas MITRE y mitigaciones candidatas. |
| `configs/bn_CPDs_template.json` | Plantilla base de CPDs probabilisticas. |
| `configs/requirements.txt` | Dependencias Python del proyecto. |

**EN**: The Excel catalog used to create scenarios must contain the information required to populate assets and dependencies in SQLite.  
**ES**: El catalogo Excel utilizado para crear escenarios debe contener la informacion necesaria para poblar activos y dependencias en SQLite.

---

## Technology Stack / Tecnologias

| Technology | Role |
| --- | --- |
| Python | Main implementation language. |
| SQLite | Persistence for scenarios, assets, dependencies, and runs. |
| Pandas / OpenPyXL | Excel catalog loading and processing. |
| NetworkX | Dependency graph construction and analysis. |
| MITRE ATT&CK STIX | Knowledge source for techniques, tactics, and mitigations. |
| pgmpy | Bayesian network construction and inference. |
| pyAgrum | Influence diagram modeling and solving. |
| PuLP | Linear optimization for countermeasure selection. |
| Rich | CLI panels, tables, dashboards, and report screens. |
| JSON / Markdown | Result export and narrative reporting. |

| Tecnologia | Uso |
| --- | --- |
| Python | Lenguaje principal de implementacion. |
| SQLite | Persistencia de escenarios, activos, dependencias y runs. |
| Pandas / OpenPyXL | Carga y procesamiento del catalogo Excel. |
| NetworkX | Construccion y analisis del grafo de dependencias. |
| MITRE ATT&CK STIX | Fuente de conocimiento para tecnicas, tacticas y mitigaciones. |
| pgmpy | Construccion e inferencia sobre redes bayesianas. |
| pyAgrum | Modelado y resolucion de diagramas de influencia. |
| PuLP | Optimizacion lineal para seleccion de contramedidas. |
| Rich | Paneles, tablas, dashboards y pantallas de reporte en CLI. |
| JSON / Markdown | Exportacion de resultados y reportes narrativos. |

---

## Design Principles / Criterios de Diseno

| Principle | Description |
| --- | --- |
| Traceability | Each recommendation can be linked to input data, threat vectors, propagation, risk, and constraints. |
| Reproducibility | Results are exported as JSON artifacts and can be persisted as runs. |
| Modularity | CLI, database, graph analysis, risk modeling, and optimization are separated into dedicated modules. |
| Explainability | The system provides the risk context behind each recommendation. |
| Analytical flexibility | Results can be compared by changing incidents, confidence levels, objectives, budget, and time constraints. |

| Criterio | Descripcion |
| --- | --- |
| Trazabilidad | Cada recomendacion puede vincularse con datos de entrada, vectores de amenaza, propagacion, riesgo y restricciones. |
| Reproducibilidad | Los resultados se exportan como artefactos JSON y pueden persistirse como runs. |
| Modularidad | CLI, base de datos, analisis de grafo, modelado de riesgo y optimizacion se separan en modulos dedicados. |
| Explicabilidad | El sistema proporciona el contexto de riesgo que justifica cada recomendacion. |
| Flexibilidad analitica | Los resultados pueden compararse variando incidentes, confianza, objetivos, presupuesto y tiempo. |

---

## Academic Scope / Alcance Academico

**EN**

This repository is part of a Final Degree Project for the Degree in Telecommunication Technologies and Services Engineering at ETSIT - Universidad Politecnica de Madrid.

The project focuses on cybersecurity risk analysis and decision support. Its main contribution is the integration of structural representation, MITRE-based threat knowledge, probabilistic inference, and countermeasure optimization within a reproducible workflow.

**ES**

Este repositorio forma parte de un Trabajo de Fin de Grado del Grado en Ingenieria de Tecnologias y Servicios de Telecomunicacion en la ETSIT - Universidad Politecnica de Madrid.

El proyecto se centra en el analisis de riesgo y el apoyo a la decision en ciberseguridad. Su contribucion principal es integrar representacion estructural, conocimiento de amenazas basado en MITRE, inferencia probabilistica y optimizacion de contramedidas dentro de un flujo reproducible.

---

## Limitations / Limitaciones

**EN**

CARE should be understood as an academic and analytical prototype:

- Results depend on the quality of the asset and dependency catalog.
- Probabilities and mitigation effects come from configurable models.
- Recommendations are decision-support outputs, not automatic actions.
- Final validation requires expert review and adaptation to the real context of use.

**ES**

CARE debe entenderse como un prototipo academico y analitico:

- Los resultados dependen de la calidad del catalogo de activos y dependencias.
- Las probabilidades y efectos de mitigacion proceden de modelos configurables.
- Las recomendaciones son salidas de apoyo a la decision, no acciones automaticas.
- La validacion final requiere revision experta y adaptacion al contexto real de uso.

---

## Author / Autor

**Sergi Gutierrez**  
Degree in Telecommunication Technologies and Services Engineering  
ETSIT - Universidad Politecnica de Madrid

Grado en Ingenieria de Tecnologias y Servicios de Telecomunicacion  
ETSIT - Universidad Politecnica de Madrid

GitHub: [serguccierrez](https://github.com/serguccierrez)

---

> **EN**: CARE turns a threat scenario into a traceable, quantitative, and reproducible countermeasure recommendation.  
> **ES**: CARE convierte un escenario de amenaza en una recomendacion trazable, cuantitativa y reproducible de contramedidas.
