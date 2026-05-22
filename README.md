# CARE - Cyber Action Recommendation Engine

**Motor de simulacion y analisis de riesgo en ciberseguridad para evaluar estrategias de mitigacion.**

CARE es un sistema de apoyo a la decision desarrollado como Trabajo de Fin de Grado. Modela activos y dependencias, simula escenarios de amenaza basados en MITRE ATT&CK, estima riesgo residual en Confidencialidad, Integridad y Disponibilidad, y permite comparar estrategias de mitigacion bajo restricciones de coste y tiempo.

El objetivo es proporcionar una base analitica, transparente y reproducible para explorar escenarios what-if y estudiar como distintas medidas preventivas podrian modificar el riesgo del sistema.

> **English summary**  
> CARE is a cybersecurity decision-support and what-if simulation engine developed as a Final Degree Project. It combines dependency graphs, MITRE ATT&CK knowledge, probabilistic inference, CIA risk assessment and constrained optimization to compare traceable mitigation strategies.

---

## Puntos Clave

- Gestion de escenarios con activos, dependencias y ejecuciones de analisis.
- Modelo de grafo dirigido para estudiar propagacion de impacto.
- Inyeccion de amenazas basada en MITRE ATT&CK, en modo aleatorio o controlado.
- Inferencia bayesiana para estimar riesgo residual.
- Agregacion de riesgo por incidente, activo y sistema en dimensiones CIA.
- Evaluacion y optimizacion de estrategias de mitigacion bajo restricciones de presupuesto y tiempo.
- Interfaz CLI con paneles, tablas, dashboards y vistas operativas.
- Generacion de informes Markdown al guardar una ejecucion.

---

## Flujo del Sistema

```text
Catalogo de activos
    |
    v
Base de datos de escenarios
    |
    v
Grafo de dependencias
    |
    v
Inyeccion de amenazas
    |
    v
Propagacion de impacto
    |
    v
Estimacion bayesiana de riesgo
    |
    v
Escenarios de mitigacion
    |
    v
Optimizacion con restricciones
    |
    v
Dashboard + JSON + Informe Markdown
```

CARE sigue un flujo de analisis completo:

1. Se carga un escenario desde un catalogo estructurado de activos y dependencias.
2. La infraestructura se representa como un grafo dirigido.
3. Se asocian vectores de amenaza a activos concretos mediante tecnicas MITRE ATT&CK.
4. El impacto potencial se propaga a traves de los niveles de dependencia.
5. Se estima el riesgo residual en Confidencialidad, Integridad y Disponibilidad.
6. Se generan escenarios de decision con mitigaciones candidatas.
7. Un modelo de optimizacion compara alternativas bajo limites de coste y tiempo.
8. Los resultados se exportan como artefactos estructurados, dashboards e informes narrativos.

---

## Capturas

### Inicializacion del sistema

![CARE init](./images/init.png)

### Gestion de escenarios

![CARE database](./images/db.png)

### Inyeccion de amenazas

![CARE attack](./images/attack.png)

### Dashboard de riesgo

![CARE dashboard](./images/dashboard.png)

### Optimizacion de mitigaciones

![CARE optimization](./images/optimize.png)

### Runs y reportes

![CARE reports](./images/reports.png)

### Informe Markdown generado

![CARE markdown report](./images/report-markdown.png)

---

## Arquitectura

```text
TFG_motor-contramedidas-ciberneticas/
|-- configs/                    # CPDs, mappings MITRE y catalogo de contramedidas
|-- data/                       # Datos de entrada y dataset local de MITRE ATT&CK
|-- images/                     # Capturas utilizadas en este README
|-- src/
|   |-- cli/                    # Vistas y comandos de la CLI CARE
|   |-- cyberrecom/             # Orquestacion del analisis end-to-end
|   |-- database/               # Esquema SQLite, carga y persistencia de reportes
|   |-- graph/                  # Construccion del grafo y analisis de dependencias
|   |-- reporting/              # Generacion de reportes JSON y Markdown
|   |-- risk/                   # Inferencia bayesiana, decision y optimizacion
|-- README.md
```

El repositorio separa responsabilidades de interfaz, persistencia, analisis de grafo, modelado de riesgo, reporting y optimizacion. Esta division permite seguir el proceso desde los datos de entrada hasta la comparativa final de escenarios.

---

## Uso Rapido

Crear y activar un entorno virtual:

```bash
python -m venv .venv
.\.venv\Scripts\activate
pip install -r configs/requirements.txt
```

Inicializar CARE:

```bash
python -m src.cli.care init
```

Cargar o crear un escenario:

```bash
python -m src.cli.care db load --scenario "<scenario_name>"
python -m src.cli.care db create --scenario "<scenario_name>" --description "<description>" --source "<excel_path>"
```

Ejecutar una simulacion aleatoria:

```bash
python -m src.cli.care attack run --random
```

Ejecutar una simulacion controlada:

```bash
python -m src.cli.care attack select --asset "<asset_id>" --ttp "T1190" --confidence 0.75
python -m src.cli.care attack run
```

Consultar resultados:

```bash
python -m src.cli.care dashboard
```

Configurar y ejecutar la optimizacion:

```bash
python -m src.cli.care optimize config --objective global --budget 50000 --time 210
python -m src.cli.care optimize run
```

Guardar una ejecucion y generar su informe Markdown:

```bash
python -m src.cli.care reports save --filename "<report_name.md>" --description "<description>"
```

Cargar una ejecucion previa:

```bash
python -m src.cli.care reports load --run_name "<run_name>"
```

---

## Superficie CLI

| Comando | Proposito |
| --- | --- |
| `init` | Inicializa el contexto de la CLI y muestra la pantalla de bienvenida. |
| `db` | Gestiona escenarios, activos y dependencias. |
| `attack` | Configura y ejecuta simulaciones de amenaza. |
| `dashboard` | Muestra el analisis de riesgo mas reciente. |
| `optimize` | Configura restricciones y ejecuta la comparacion optimizada de mitigaciones. |
| `reports` | Lista, guarda y restaura ejecuciones persistidas. |

---

## Artefactos Generados

| Artefacto | Descripcion |
| --- | --- |
| `src/cli/context.json` | Estado actual de la sesion CLI. |
| `configs/bn_CPDs.json` | CPDs dinamicas utilizadas durante la inferencia bayesiana. |
| `src/reporting/report.json` | Reporte estructurado del analisis de riesgo. |
| `src/reporting/optimization_solution.json` | Resultado de optimizacion y mitigaciones seleccionadas en la simulacion. |
| `src/reporting/<run_name>.md` | Informe narrativo generado al guardar una ejecucion. |
| `src/database/tfg_catalog.db` | Base de datos SQLite con escenarios, activos, dependencias y runs. |

---

## Datos y Configuracion

| Fichero | Funcion |
| --- | --- |
| `data/enterprise-attack.json` | Dataset local de MITRE ATT&CK Enterprise. |
| `configs/countermeasures.json` | Catalogo de mitigaciones con coste, tiempo de despliegue y efecto esperado. |
| `configs/ttps_to_mitigations.json` | Relacion entre tecnicas MITRE y mitigaciones candidatas. |
| `configs/bn_CPDs_template.json` | Plantilla base de CPDs probabilisticas. |
| `configs/requirements.txt` | Dependencias Python del proyecto. |

---

## Tecnologias

| Tecnologia | Uso |
| --- | --- |
| Python | Lenguaje principal de implementacion. |
| SQLite | Persistencia de escenarios, activos, dependencias y ejecuciones. |
| Pandas / OpenPyXL | Carga y procesamiento del catalogo Excel. |
| NetworkX | Construccion y recorrido del grafo de dependencias. |
| MITRE ATT&CK STIX | Fuente de conocimiento sobre tecnicas, tacticas y mitigaciones. |
| pgmpy | Inferencia sobre redes bayesianas. |
| pyAgrum | Modelado de diagramas de influencia. |
| PuLP | Optimizacion lineal. |
| Rich | Interfaz en terminal, tablas, paneles y dashboards. |
| JSON / Markdown | Exportacion estructurada y reporting narrativo. |

---

## Criterios de Diseno

| Criterio | Significado |
| --- | --- |
| Trazabilidad | Los resultados pueden vincularse con datos de escenario, amenazas, propagacion, riesgo y restricciones. |
| Reproducibilidad | Las ejecuciones pueden exportarse, almacenarse y restaurarse. |
| Modularidad | Datos, grafo, riesgo, optimizacion, reporting y CLI se mantienen separados. |
| Explicabilidad | El sistema expone el contexto de riesgo que justifica cada comparativa de mitigacion. |
| Flexibilidad analitica | Pueden variar incidentes, confianzas, objetivos, presupuesto y tiempo disponible. |

---

## Alcance Academico

Este repositorio forma parte de un **Trabajo de Fin de Grado** del Grado en Ingenieria de Tecnologias y Servicios de Telecomunicacion en la **ETSIT - Universidad Politecnica de Madrid**.

El proyecto se centra en el analisis de riesgo, la simulacion de escenarios y el apoyo a la decision en ciberseguridad. Su aportacion principal es integrar modelado estructural de dependencias, conocimiento de amenazas basado en MITRE, estimacion probabilistica de riesgo y optimizacion de mitigaciones dentro de un flujo reproducible.

---

## Limitaciones

CARE es un prototipo academico y analitico:

- Los resultados dependen de la calidad del catalogo de activos y dependencias.
- Las probabilidades y efectos de mitigacion proceden de modelos configurables.
- Los resultados deben interpretarse como apoyo a la decision y analisis what-if, no como acciones automaticas.
- La validacion final requiere revision experta y adaptacion al contexto real de uso.

---

## Author

**Sergi Gutierrez**  
Grado en Ingenieria de Tecnologias y Servicios de Telecomunicacion  
ETSIT - Universidad Politecnica de Madrid

GitHub: [serguccierrez](https://github.com/serguccierrez)

---

> CARE convierte un escenario de amenaza en una comparativa trazable, cuantitativa y reproducible de estrategias de mitigacion.
