# Caso de uso de validación final

## Identificación del caso

Este documento resume el caso de uso elegido para la validación de resultados del TFG. El escenario representa una topología corporativa compacta de una empresa mediana con servicios de identidad, acceso remoto, aplicaciones de negocio, repositorios de datos, almacenamiento SaaS, virtualización y copias de seguridad.

La idea principal del caso es que sea fácil de explicar ante el tribunal, pero suficientemente expresivo para mostrar propagación, inferencia bayesiana, optimización por dominios CIA y evaluación de riesgo residual.

| Elemento | Valor |
|---|---|
| Escenario | `validacion_corp_compacta_web_v4_weighted` |
| Catálogo Excel | `data/validacion_corp_compacta_web_v4_weighted.xlsx` |
| Activos | 17 |
| Dependencias | 26 |
| Densidad del grafo | 0.0956 |
| Modo de ataque | `controlled` |
| Presupuesto de optimización | 70000 |
| Tiempo máximo por contramedida | 30 horas |
| Contexto CLI | `src/cli/context.json` |
| Informe bruto | `src/reporting/report.json` |
| Solución de optimización | `src/reporting/optimization_solution.json` |
| Resumen final | `src/reporting/validation_logs_config/validacion_corp_compacta_web_v4_weighted_setC_calibrated_final_summary.json` |

## Planteamiento narrativo

La organización ficticia, denominada ACME, opera un portal de clientes conectado con sistemas internos de ERP y CRM. La empresa utiliza un proveedor de identidad corporativo para SSO, una VPN para acceso remoto, una plataforma EDR en los puestos de trabajo, un SIEM para monitorización, un entorno de virtualización para alojar aplicaciones y bases de datos, almacenamiento SaaS para documentos y un repositorio de copias de seguridad.

El caso de uso modela un incidente multietapa. El atacante obtiene un primer punto de entrada mediante phishing sobre los equipos corporativos. Después consigue credenciales con valor operativo, alcanza el proveedor de identidad, ejecuta comandos en el entorno virtualizado, exfiltra información desde el almacenamiento SaaS y finalmente intenta inhibir la recuperación atacando el repositorio de copias de seguridad.

La narrativa es coherente porque combina tres ideas habituales en incidentes corporativos: compromiso inicial en endpoint, abuso de identidad como punto de pivote y presión sobre recuperación mediante impacto sobre backups. Además, genera riesgos diferentes en confidencialidad, integridad y disponibilidad, lo que permite justificar la comparación entre objetivos de optimización.

## Catálogo del escenario

| Activo | Descripción | Criticidad | Peso C | Peso I | Peso A |
|---|---:|---:|---:|---:|---:|
| `ACME_IDP` | Identity provider / SSO | 0.97 | 0.20 | 0.50 | 0.30 |
| `ACME_VPN` | Remote access VPN | 0.82 | 0.20 | 0.30 | 0.50 |
| `ACME_FW` | Perimeter firewall | 0.84 | 0.15 | 0.30 | 0.55 |
| `ACME_WAF` | Customer portal WAF | 0.78 | 0.25 | 0.30 | 0.45 |
| `ACME_EDR` | Endpoint protection platform | 0.82 | 0.20 | 0.40 | 0.40 |
| `ACME_SIEM` | SIEM and SOC console | 0.86 | 0.30 | 0.50 | 0.20 |
| `ACME_PORTAL` | Customer portal | 0.88 | 0.40 | 0.25 | 0.35 |
| `ACME_ERP` | Corporate ERP | 0.96 | 0.20 | 0.55 | 0.25 |
| `ACME_CRM` | Commercial CRM | 0.88 | 0.55 | 0.30 | 0.15 |
| `ACME_ERP_DB` | ERP database | 0.97 | 0.30 | 0.55 | 0.15 |
| `ACME_CRM_DB` | CRM database | 0.91 | 0.65 | 0.25 | 0.10 |
| `ACME_DWH` | Business data warehouse | 0.92 | 0.70 | 0.20 | 0.10 |
| `ACME_FILES` | Document repository | 0.84 | 0.60 | 0.20 | 0.20 |
| `ACME_CLOUD` | SaaS storage tenant | 0.90 | 0.70 | 0.20 | 0.10 |
| `ACME_VIRT` | Virtualization cluster | 0.95 | 0.10 | 0.30 | 0.60 |
| `ACME_BACKUP` | Backup repository | 0.96 | 0.20 | 0.20 | 0.60 |
| `ACME_ENDPOINTS` | Corporate workstations | 0.72 | 0.25 | 0.25 | 0.50 |

## Grafo de dependencias

El grafo se mantiene deliberadamente compacto: 17 nodos y 26 aristas. Esto permite representarlo en memoria o en una figura sin que se vuelva ilegible, pero conserva dependencias suficientes para que la propagación no sea trivial.

Para explicar el caso de uso como arquitectura corporativa, la topología conceptual simplificada queda guardada en `figuras-latex/topologia_red_simplificada_caso_validacion_final.svg`. También se incluye una versión editable en Mermaid en `figuras-latex/topologia_red_simplificada_caso_validacion_final.mmd`.

![Topologia de red del caso de validacion](../figuras-latex/topologia_red_simplificada_caso_validacion_final.svg)

La representación del grafo de dependencias del modelo queda guardada aparte en `figuras-latex/topologia_caso_validacion_final.svg`. Esa segunda figura es más útil para justificar la construcción del grafo y la propagación.

| Grupo funcional | Dependencias |
|---|---|
| Identidad corporativa | `ACME_VPN -> ACME_IDP`, `ACME_PORTAL -> ACME_IDP`, `ACME_ERP -> ACME_IDP`, `ACME_CRM -> ACME_IDP`, `ACME_CLOUD -> ACME_IDP` |
| Controles perimetrales y seguridad | `ACME_PORTAL -> ACME_WAF`, `ACME_VPN -> ACME_FW`, `ACME_ENDPOINTS -> ACME_EDR`, `ACME_SIEM -> ACME_EDR` |
| Plataforma de virtualización | `ACME_ERP -> ACME_VIRT`, `ACME_CRM -> ACME_VIRT`, `ACME_ERP_DB -> ACME_VIRT`, `ACME_CRM_DB -> ACME_VIRT`, `ACME_FILES -> ACME_VIRT` |
| Flujos de datos de negocio | `ACME_ERP -> ACME_ERP_DB`, `ACME_CRM -> ACME_CRM_DB`, `ACME_DWH -> ACME_ERP_DB`, `ACME_PORTAL -> ACME_CRM_DB`, `ACME_FILES -> ACME_CLOUD`, `ACME_DWH -> ACME_CLOUD` |
| Recuperación | `ACME_ERP_DB -> ACME_BACKUP`, `ACME_CRM_DB -> ACME_BACKUP`, `ACME_FILES -> ACME_BACKUP` |
| Exposición del portal | `ACME_ERP -> ACME_PORTAL`, `ACME_CRM -> ACME_PORTAL`, `ACME_DWH -> ACME_PORTAL` |

## Configuración del ataque

El ataque utiliza cinco TTPs. El número es razonable para un caso académico: permite representar una cadena de ataque completa sin convertir el ejemplo en una campaña excesivamente compleja.

| TTP | Nombre | Táctica | Activo inicial | Confianza | Nodos afectados | Profundidad | Papel narrativo |
|---|---|---|---|---:|---:|---:|---|
| `T1566` | Phishing | initial-access | `ACME_ENDPOINTS` | 0.72 | 1 | 0 | Entrada inicial mediante usuarios corporativos |
| `T1003` | OS Credential Dumping | credential-access | `ACME_IDP` | 0.82 | 8 | 2 | Obtención de credenciales y pivote sobre identidad |
| `T1059` | Command and Scripting Interpreter | execution | `ACME_VIRT` | 0.70 | 8 | 2 | Ejecución sobre infraestructura virtualizada |
| `T1048` | Exfiltration Over Alternative Protocol | exfiltration | `ACME_CLOUD` | 0.78 | 3 | 1 | Salida de información por canal no estándar |
| `T1490` | Inhibit System Recovery | impact | `ACME_BACKUP` | 0.74 | 8 | 2 | Degradación de la capacidad de recuperación |

La lista equivalente en el contexto de ejecución es:

```json
{
  "active_scenario": "validacion_corp_compacta_web_v4_weighted",
  "mode": "controlled",
  "selected_asset": [
    "ACME_ENDPOINTS",
    "ACME_IDP",
    "ACME_VIRT",
    "ACME_CLOUD",
    "ACME_BACKUP"
  ],
  "selected_ttps": [
    "T1566",
    "T1003",
    "T1059",
    "T1048",
    "T1490"
  ],
  "selected_confidences": [
    0.72,
    0.82,
    0.70,
    0.78,
    0.74
  ],
  "optimization_objective": "all",
  "optimization_budget": 70000.0,
  "optimization_time": 30.0
}
```

## Propagación del impacto

La propagación queda repartida entre dominios diferentes:

| TTP | Activos afectados por nivel |
|---|---|
| `T1566` | Nivel 0: `ACME_ENDPOINTS` |
| `T1003` | Nivel 0: `ACME_IDP`; nivel 1: `ACME_PORTAL`, `ACME_ERP`, `ACME_CRM`, `ACME_VPN`, `ACME_CLOUD`; nivel 2: `ACME_DWH`, `ACME_FILES` |
| `T1059` | Nivel 0: `ACME_VIRT`; nivel 1: `ACME_ERP`, `ACME_CRM`, `ACME_ERP_DB`, `ACME_CRM_DB`, `ACME_FILES`; nivel 2: `ACME_DWH`, `ACME_PORTAL` |
| `T1048` | Nivel 0: `ACME_CLOUD`; nivel 1: `ACME_FILES`, `ACME_DWH` |
| `T1490` | Nivel 0: `ACME_BACKUP`; nivel 1: `ACME_ERP_DB`, `ACME_CRM_DB`, `ACME_FILES`; nivel 2: `ACME_ERP`, `ACME_DWH`, `ACME_CRM`, `ACME_PORTAL` |

Esto ayuda a explicar que el incidente no afecta a todos los activos por igual. Identidad y virtualización generan propagación amplia; nube y backups activan riesgos más específicos en confidencialidad y disponibilidad.

## Resultados de inferencia bayesiana

Riesgo inicial obtenido antes de aplicar contramedidas:

| Dimensión | Riesgo inicial |
|---|---:|
| Confidencialidad | 5.1483 |
| Integridad | 5.0131 |
| Disponibilidad | 4.6583 |
| Global | 4.9557 |

La dispersión entre dimensiones antes de mitigar es de 0.4900. Esto es útil narrativamente porque evita un caso plano: confidencialidad e integridad quedan ligeramente por encima de disponibilidad, pero las tres dimensiones siguen siendo relevantes.

## Resultados del diagrama de influencia y optimización

La optimización global con presupuesto 70000 y tiempo máximo de 30 horas por contramedida produce una solución óptima con 12 activos mitigados y 7 tipos distintos de contramedida.

| Métrica | Valor |
|---|---:|
| Riesgo global inicial | 4.9557 |
| Riesgo global residual | 2.9409 |
| Reducción absoluta | 2.0147 |
| Reducción relativa | 40.7 % |
| Coste usado | 70000 |
| Activos con contramedida | 12 |
| Variedad de contramedidas | 7 |

Riesgo residual de la solución global:

| Dimensión | Riesgo residual | Reducción aproximada |
|---|---:|---:|
| Confidencialidad | 3.4074 | 33.8 % |
| Integridad | 2.9006 | 42.1 % |
| Disponibilidad | 2.9960 | 35.7 % |
| Global | 2.9409 | 40.7 % |

## Contramedidas seleccionadas en la solución global

| Activo | Contramedida | Nombre | Coste | Tiempo |
|---|---|---|---:|---:|
| `ACME_ENDPOINTS` | `M1021` | Restrict Web-Based Content | 3500 | 10 |
| `ACME_IDP` | `M1028` | Operating System Configuration | 5000 | 20 |
| `ACME_PORTAL` | `none` | Sin contramedida en la solución global | 0 | 0 |
| `ACME_ERP` | `M1040` | Behavior Prevention on Endpoint | 10000 | 24 |
| `ACME_CRM` | `M1040` | Behavior Prevention on Endpoint | 10000 | 24 |
| `ACME_VPN` | `M1028` | Operating System Configuration | 5000 | 20 |
| `ACME_CLOUD` | `M1022` | Restrict File and Directory Permissions | 2500 | 8 |
| `ACME_DWH` | `M1022` | Restrict File and Directory Permissions | 2500 | 8 |
| `ACME_FILES` | `M1018` | User Account Management | 4000 | 16 |
| `ACME_VIRT` | `M1040` | Behavior Prevention on Endpoint | 10000 | 24 |
| `ACME_ERP_DB` | `M1038` | Execution Prevention | 7000 | 22 |
| `ACME_CRM_DB` | `M1021` | Restrict Web-Based Content | 3500 | 10 |
| `ACME_BACKUP` | `M1053` | Data Backup | 7000 | 16 |

Distribución por contramedida en la solución global:

| Contramedida | Usos |
|---|---:|
| `M1040` | 3 |
| `M1021` | 2 |
| `M1028` | 2 |
| `M1022` | 2 |
| `M1018` | 1 |
| `M1038` | 1 |
| `M1053` | 1 |
| `none` | 1 |

## Comparación por objetivos

| Objetivo | Riesgo global residual | C residual | I residual | A residual | Coste | Variedad |
|---|---:|---:|---:|---:|---:|---:|
| Global | 2.9409 | 3.4074 | 2.9006 | 2.9960 | 70000 | 7 |
| Confidencialidad | 3.1908 | 2.7571 | 2.9480 | 3.7492 | 69500 | 5 |
| Integridad | 3.0826 | 3.5625 | 2.4226 | 3.2492 | 69500 | 4 |
| Disponibilidad | 3.1346 | 3.7685 | 2.9068 | 2.9262 | 70000 | 5 |

Esta comparación es especialmente útil para la memoria. La optimización por dimensión consigue reducir mejor el dominio que prioriza, pero empeora el equilibrio global. La solución global es más defendible como propuesta ejecutiva porque ofrece una reducción alta, mantiene los tres dominios en un rango parecido y selecciona una cartera de mitigaciones más variada.

## Lectura académica de los resultados

El caso permite defender tres conclusiones:

1. La identidad corporativa y la virtualización actúan como puntos de propagación de alto impacto. No son simplemente activos críticos por criticidad individual, sino por las dependencias que arrastran.
2. La optimización global no se limita a elegir la contramedida más fuerte de forma repetida. Distribuye controles sobre endpoints, identidad, permisos, ejecución, comportamiento y backup, lo que genera una estrategia más realista.
3. El riesgo residual no desaparece. El portal de clientes queda sin contramedida directa en la solución global porque, bajo el presupuesto disponible, el modelo prioriza controles que reducen mejor el riesgo ponderado de la cadena completa.

## Redacción breve para la sección de resultados

Una formulación posible para la memoria:

> El escenario evaluado representa una red corporativa compacta formada por 17 activos y 26 dependencias. El caso combina servicios de identidad, acceso remoto, aplicaciones corporativas, repositorios de datos, almacenamiento SaaS, virtualización y copias de seguridad. Sobre esta topología se modeló una cadena de ataque compuesta por cinco técnicas MITRE ATT&CK: phishing, volcado de credenciales, ejecución mediante intérprete de comandos, exfiltración por canal alternativo e inhibición de la recuperación. La configuración permite observar propagación diferenciada entre activos y genera una distribución de riesgo no uniforme en confidencialidad, integridad y disponibilidad.
>
> Antes de aplicar contramedidas, el riesgo global estimado fue de 4.9557, con valores de 5.1483 en confidencialidad, 5.0131 en integridad y 4.6583 en disponibilidad. Tras resolver el problema de optimización con un presupuesto de 70000 y un tiempo máximo de despliegue de 30 horas por contramedida, la solución global redujo el riesgo residual a 2.9409, lo que supone una reducción aproximada del 40.7 %. La solución seleccionó 7 tipos distintos de contramedida y mitigó 12 activos, mostrando una estrategia equilibrada frente a las soluciones orientadas exclusivamente a una dimensión CIA.

## Comandos de reproducción

El contexto final queda guardado en `src/cli/context.json`. Si el escenario no existe todavía en la base de datos local, primero hay que crearlo desde el Excel:

```powershell
python -m src.cli.care db create --scenario validacion_corp_compacta_web_v4_weighted --description "Caso de validacion final corporativo compacto" --source data\validacion_corp_compacta_web_v4_weighted.xlsx
```

Después, la ejecución exacta puede reproducirse desde consola con el contexto activo:

```powershell
python -m src.cli.care db load --scenario validacion_corp_compacta_web_v4_weighted
python -m src.cli.care attack run
python -m src.cli.care optimize run
```

En este caso, el parámetro de tiempo representa el tiempo máximo de despliegue permitido para cada contramedida individual, no la suma total del tiempo de despliegue de todas las contramedidas seleccionadas.

La ejecución se comprobó desde consola el 23 de mayo de 2026: el ataque generó un riesgo global de 4.96/10 y la optimización obtuvo solución óptima con riesgo residual global de 2.94/10.
