"""
Se guardan y recuperan informes de ejecución en la base de datos SQLite.
También se genera un informe narrativo en Markdown a partir de los JSON producidos por CARE.
"""

#=============================================================[IMPORTS]===============================================
import json
import sqlite3
from pathlib import Path

import src.graph.grafo as grafo


#=============================================================[FUNCTIONS]===============================================
def save_reports_to_db(db_path: str, run_name: str, description: str, context_json_path: str, bn_cpds_json_path: str, reports_json_path: str, optimization_json_path: str, narrative_report_path: str):
    """
    Guarda en base de datos los artefactos generados por una ejecución.
    Se leen los JSON disponibles, el informe narrativo y se asocian al escenario activo.

    Args:
        db_path: Ruta del fichero .db donde se guarda la ejecución.
        run_name: Nombre identificativo de la ejecución.
        context_json_path: Ruta del JSON de contexto.
        bn_cpds_json_path: Ruta opcional del JSON con CPDs de la red bayesiana.
        reports_json_path: Ruta opcional del JSON de reporte de riesgo.
        optimization_json_path: Ruta opcional del JSON de optimización.
        narrative_report_path: Ruta opcional del informe narrativo en texto.

    Returns:
        None. Se inserta un nuevo registro en la tabla runs.
    """
    # Se leen los archivos JSON y el informe narrativo disponibles
    with open(context_json_path, 'r', encoding='utf-8') as f:
        context_json = json.load(f)

    if bn_cpds_json_path is not None:
        with open(bn_cpds_json_path, 'r', encoding='utf-8') as f:
            bn_cpds_json = json.load(f)
    else:
        bn_cpds_json = None

    if reports_json_path is not None:
        with open(reports_json_path, 'r', encoding='utf-8') as f:
            reports_json = json.load(f)
    else:
        reports_json = None

    if optimization_json_path is not None:
        with open(optimization_json_path, 'r', encoding='utf-8') as f:
            optimization_json = json.load(f)
    else:
        optimization_json = None

    if narrative_report_path is not None:
        with open(narrative_report_path, 'r', encoding='utf-8') as f:
            narrative_report = f.read()
    else:
        narrative_report = None

    # Se abre la conexión con la base de datos SQLite
    conn = sqlite3.connect(db_path)

    try:
        conn.execute("PRAGMA foreign_keys = ON;")
        cursor = conn.cursor()

        # Se obtiene el escenario activo indicado en el contexto de ejecución
        scenario_name = context_json["active_scenario"]
        scenario_fk = grafo.get_scenario_pk(db_path, scenario_name)
        
        # Se registra la ejecución junto con sus artefactos serializados
        cursor.execute(
            """
            INSERT INTO runs (scenario_fk, run_name, description, context_json, bn_cpds_json, reports_json, optimization_json, narrative_report)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                scenario_fk,
                run_name,
                description,
                json.dumps(context_json, ensure_ascii=False),
                json.dumps(bn_cpds_json, ensure_ascii=False) if bn_cpds_json is not None else None,
                json.dumps(reports_json, ensure_ascii=False) if reports_json is not None else None,
                json.dumps(optimization_json, ensure_ascii=False) if optimization_json is not None else None,
                narrative_report
            )
        )
        
        # Se confirman los cambios en la base de datos
        conn.commit()

    finally:
        # Se cierra la conexión con la base de datos
        conn.close()


def list_runs(db_path: str, scenario_name: str = None):
    """
    Lista ejecuciones almacenadas en la base de datos.
    Se puede filtrar por escenario cuando se proporciona su nombre.

    Args:
        db_path: Ruta del fichero .db que contiene las ejecuciones.
        scenario_name: Nombre opcional del escenario por el que se filtra.

    Returns:
        Lista de tuplas con run_pk, run_name, description y created_at.
    """
    conn = sqlite3.connect(db_path)
    try:
        cursor = conn.cursor()
        
        # Se filtran las ejecuciones por escenario si se indica uno concreto
        if scenario_name:
            scenario_fk = grafo.get_scenario_pk(db_path, scenario_name)
            cursor.execute("SELECT run_pk, run_name, description, created_at FROM runs WHERE scenario_fk = ?", (scenario_fk,))
        else:
            cursor.execute("SELECT run_pk, run_name, description, created_at FROM runs")
            
        runs = cursor.fetchall()
        return runs
    finally:
        # Se cierra la conexión con la base de datos
        conn.close()
        
        
def get_run_reports(db_path: str, run_name: str):
    """
    Recupera los informes asociados a una ejecución concreta.
    Se deserializan los campos JSON antes de devolverlos al llamador.

    Args:
        db_path: Ruta del fichero .db donde se buscan los informes.
        run_name: Nombre de la ejecución que se desea recuperar.

    Returns:
        Tuple con contexto, CPDs, reporte, optimización e informe narrativo.
        Devuelve None si no se encuentra la ejecución.
    """
    conn = sqlite3.connect(db_path)
    try:
        cursor = conn.cursor()
        
        # Se localizan los artefactos guardados para la ejecución solicitada
        cursor.execute("SELECT context_json, bn_cpds_json, reports_json, optimization_json, narrative_report FROM runs WHERE run_name = ?", (run_name,))
        result = cursor.fetchone()
        
        if result:
            context_json_str, bn_cpds_json_str, reports_json_str, optimization_json_str, narrative_report = result
            context_json = json.loads(context_json_str) if context_json_str else None
            bn_cpds_json = json.loads(bn_cpds_json_str) if bn_cpds_json_str else None
            reports_json = json.loads(reports_json_str) if reports_json_str else None
            optimization_json = json.loads(optimization_json_str) if optimization_json_str else None
            
            return context_json, bn_cpds_json, reports_json, optimization_json, narrative_report
    
    finally:
        # Se cierra la conexión con la base de datos
        conn.close()
        

def generate_report_md(context_json_path: str = None, reports_json_path: str = None, optimization_json_path: str = None, output_path: str = None):
    """
    Genera un informe narrativo en Markdown a partir de los últimos JSON generados.
    Se combinan contexto, reporte de riesgo y resultados de optimización.

    Args:
        context_json_path: Ruta opcional del JSON de contexto.
        reports_json_path: Ruta opcional del JSON de reporte de riesgo.
        optimization_json_path: Ruta opcional del JSON de optimización.
        output_path: Ruta opcional donde se escribe el informe Markdown.

    Returns:
        Contenido completo del informe generado en formato Markdown.
    """
    # Se resuelven rutas por defecto para los artefactos de entrada y salida
    base_path = Path(__file__).parent.parent.parent
    
    context_json_path = Path(context_json_path) if context_json_path is not None else base_path / "src" / "cli" / "context.json"
    reports_json_path = Path(reports_json_path) if reports_json_path is not None else base_path / "src" / "reporting" / "report.json"
    optimization_json_path = Path(optimization_json_path) if optimization_json_path is not None else base_path / "src" / "reporting" / "optimization_solution.json"
    output_path = Path(output_path) if output_path is not None else base_path / "src" / "reporting" / "generated_report.md"
    
    def load_json_file(json_path: Path):
        """
        Carga un archivo JSON si existe.

        Args:
            json_path: Ruta del archivo JSON que se intenta cargar.

        Returns:
            Diccionario con el contenido del JSON o None si no existe.
        """
        if json_path.exists():
            with open(json_path, "r", encoding="utf-8") as f:
                return json.load(f)
        return None
    
    def format_number(value):
        """
        Formatea valores numéricos para mostrarlos en el informe.

        Args:
            value: Valor que se va a representar.

        Returns:
            Valor formateado con tres decimales o N/A si no existe.
        """
        if isinstance(value, float):
            return f"{value:.3f}"
        return value if value is not None else "N/A"

    def format_delta(value):
        """
        Formatea variaciones numéricas con signo.

        Args:
            value: Valor de variación que se va a representar.

        Returns:
            Texto con la variación formateada o N/A si no es numérica.
        """
        if not isinstance(value, (int, float)):
            return "N/A"
        sign = "+" if value > 0 else ""
        return f"{sign}{value:.3f}"

    def color_text(text, color):
        """
        Envuelve texto en una etiqueta HTML con color.

        Args:
            text: Texto que se desea colorear.
            color: Color CSS aplicado al texto.

        Returns:
            Cadena HTML con el texto resaltado.
        """
        return f'<span style="color:{color}"><strong>{text}</strong></span>'

    def risk_color(value):
        """
        Asigna un color visual en función del nivel de riesgo.

        Args:
            value: Valor de riesgo que se evalúa.

        Returns:
            Código de color CSS asociado al nivel de riesgo.
        """
        if not isinstance(value, (int, float)):
            return "#AAB2BF"
        if 0.0 <= value < 2.5:
            return "#2ECC71"
        if 2.5 <= value < 5.0:
            return "#F1C40F"
        if 5.0 <= value < 7.5:
            return "#E67E22"
        return "#E74C3C"

    def format_risk_value(value):
        """
        Formatea un valor de riesgo con color asociado.

        Args:
            value: Valor de riesgo que se va a mostrar.

        Returns:
            Texto HTML con el valor de riesgo coloreado.
        """
        if not isinstance(value, (int, float)):
            return "N/A"
        return color_text(format_number(value), risk_color(value))

    def format_delta_value(value):
        """
        Formatea una variación de riesgo con color según mejora o empeoramiento.

        Args:
            value: Variación de riesgo que se va a mostrar.

        Returns:
            Texto HTML con la variación coloreada.
        """
        if not isinstance(value, (int, float)):
            return "N/A"
        if value < 0:
            color = "#2ECC71"
        elif value > 0:
            color = "#E74C3C"
        else:
            color = "#F1C40F"
        return color_text(format_delta(value), color)

    def get_report_assets(report_data):
        """
        Extrae los activos analizados desde el JSON de reporte.

        Args:
            report_data: Diccionario con el reporte de riesgo.

        Returns:
            Diccionario indexado por identificador de activo.
        """
        assets = {}
        for block in report_data.get("nodes_analysis", []):
            for asset_id, asset_info in block.items():
                assets[asset_id] = asset_info
        return assets

    def build_optimization_comparison(report_data, optimization_data, objective):
        """
        Construye una comparativa de riesgo antes y después de la optimización.
        Se ponderan los riesgos optimizados por criticidad de los activos.

        Args:
            report_data: Diccionario con el reporte de riesgo base.
            optimization_data: Diccionario con la solución de optimización.
            objective: Objetivo de optimización seleccionado.

        Returns:
            Diccionario con riesgos antes, después y delta del objetivo.
        """
        if not optimization_data:
            return {}

        assets_decisions = optimization_data.get("assets_decisions", {})
        total_criticality = float(optimization_data.get("total_criticality", 0.0) or 0.0)

        risk_before = {
            "global": float(report_data.get("global_system_risk", {}).get("overall_risk", 0.0) or 0.0),
            "confidentiality": float(report_data.get("global_system_risk", {}).get("confidentiality_risk", 0.0) or 0.0),
            "integrity": float(report_data.get("global_system_risk", {}).get("integrity_risk", 0.0) or 0.0),
            "availability": float(report_data.get("global_system_risk", {}).get("availability_risk", 0.0) or 0.0),
        }

        if total_criticality:
            risk_after = {
                "global": sum(float(decision.get("risk_total", 0.0) or 0.0) * float(decision.get("criticality", 0.0) or 0.0) for decision in assets_decisions.values()) / total_criticality,
                "confidentiality": sum(float(decision.get("asset_risk_C", 0.0) or 0.0) * float(decision.get("criticality", 0.0) or 0.0) for decision in assets_decisions.values()) / total_criticality,
                "integrity": sum(float(decision.get("asset_risk_I", 0.0) or 0.0) * float(decision.get("criticality", 0.0) or 0.0) for decision in assets_decisions.values()) / total_criticality,
                "availability": sum(float(decision.get("asset_risk_A", 0.0) or 0.0) * float(decision.get("criticality", 0.0) or 0.0) for decision in assets_decisions.values()) / total_criticality,
            }
        else:
            risk_after = dict(risk_before)

        objective_key = objective if objective in risk_before else "global"

        return {
            "objective": objective_key,
            "risk_before": risk_before,
            "risk_after": risk_after,
            "objective_before": risk_before[objective_key],
            "objective_after": risk_after[objective_key],
            "objective_delta": risk_after[objective_key] - risk_before[objective_key],
        }
    
    # Se cargan los artefactos JSON necesarios para construir el informe
    context_json = load_json_file(context_json_path)
    reports_json = load_json_file(reports_json_path)
    optimization_json = load_json_file(optimization_json_path)
    
    context_json = context_json or {}
    reports_json = reports_json or {}
    optimization_json = optimization_json or {}
    
    # Se extraen datos principales del contexto y del reporte de riesgo
    scenario_name = context_json["active_scenario"]
    mode = context_json["mode"] 
    selected_assets = context_json["selected_asset"]
    selected_ttps = context_json["selected_ttps"]
    selected_confidences = context_json["selected_confidences"]
    
    metadata = reports_json["metadata"]
    threat_vectors = reports_json["threat_vectors"]
    graph_metadata = reports_json["graph_metadata"]
    global_system_risk = reports_json["global_system_risk"]
    
    # Se prepara la lista de activos ordenada por riesgo medio
    nodes_risk = []
    for block in reports_json["nodes_analysis"]:
        for asset_id, asset_info in block.items():
            nodes_risk.append((
                asset_id,
                asset_info["node_data"]["name"],
                asset_info["asset_average_risk"],
                asset_info["asset_confidentiality_risk"],
                asset_info["asset_integrity_risk"],
                asset_info["asset_availability_risk"],
            ))
            
    nodes_risk = sorted(nodes_risk, key=lambda item: item[2], reverse=True)
    
    # Se selecciona el resultado de optimización correspondiente al objetivo activo
    optimization_objective = context_json["optimization_objective"]
    if optimization_objective and optimization_objective in optimization_json:
        optimization_result = optimization_json[optimization_objective]
    elif optimization_json:
        optimization_objective = next(iter(optimization_json))
        optimization_result = optimization_json[optimization_objective]
    else:
        optimization_result = {}
    
    # Se construye el contenido Markdown del informe
    lines = []
    lines.append("# Informe de Analisis CARE")
    lines.append("")
    lines.append(f"**Escenario:** {scenario_name}")
    lines.append(f"**Fecha de generacion:** {metadata['timestamp']}")
    lines.append("")
    lines.append("## Resumen ejecutivo")
    lines.append("")
    lines.append(
        "El presente informe recoge los resultados principales de la ultima ejecucion de analisis "
        "realizada por CARE. El objetivo es ofrecer una vision sintetica del estado de riesgo del "
        "escenario evaluado, las amenazas consideradas y las medidas de mitigacion recomendadas por "
        "el proceso de optimizacion."
    )
    lines.append("")
    lines.append("Los indicadores principales de la ejecucion son los siguientes:")
    lines.append("")
    lines.append(f"- Escenario analizado: {scenario_name}")
    lines.append(f"- Modo de ejecucion: {mode}")
    lines.append(f"- Amenazas analizadas: {len(threat_vectors)}")
    lines.append(f"- Activos del grafo: {graph_metadata['total_nodes']}")
    lines.append(f"- Dependencias del grafo: {graph_metadata['total_edges']}")
    lines.append(f"- Riesgo global medio: {format_number(global_system_risk['overall_risk'])}")
    
    if optimization_result:
        optimization_comparison = build_optimization_comparison(
            reports_json,
            optimization_result,
            optimization_objective,
        )
        lines.append(f"- Objetivo de optimizacion: {optimization_objective}")
        lines.append(f"- Reduccion de riesgo estimada: {format_number(optimization_result['risk_reduction'])}")
        if optimization_comparison:
            lines.append(
                f"- Riesgo objetivo antes/despues: "
                f"{format_number(optimization_comparison['objective_before'])} -> "
                f"{format_number(optimization_comparison['objective_after'])} "
                f"({format_delta(optimization_comparison['objective_delta'])})"
            )
        lines.append(f"- Coste total recomendado: {format_number(optimization_result['total_cost'])}")
    else:
        optimization_comparison = {}
    
    lines.append("")
    lines.append(
        f"En terminos generales, el escenario presenta un riesgo medio global de "
        f"{format_number(global_system_risk['overall_risk'])}. Este valor resume el impacto estimado "
        "sobre confidencialidad, integridad y disponibilidad, ponderando los activos analizados segun "
        "su criticidad dentro del sistema."
    )
    
    if optimization_result:
        lines.append("")
        lines.append(
            f"La optimizacion se ha orientado al objetivo `{optimization_objective}` y propone una "
            f"reduccion estimada de riesgo de {format_number(optimization_result['risk_reduction'])}, "
            f"con un coste total de {format_number(optimization_result['total_cost'])}."
        )
    
    lines.append("")
    lines.append("## Analisis detallado")
    lines.append("")
    lines.append("### Contexto de la ejecucion")
    lines.append("")
    lines.append(
        f"La ejecucion se ha realizado sobre el escenario `{scenario_name}` en modo `{mode}`. "
        "Los datos empleados proceden de los artefactos JSON generados por la ultima run del motor, "
        "incluyendo el contexto operativo, el reporte de riesgo y, cuando esta disponible, la solucion "
        "de optimizacion."
    )
    
    if selected_assets or selected_ttps:
        lines.append("")
        lines.append("Configuracion seleccionada:")
        lines.append(f"- Activos seleccionados: {', '.join(selected_assets) if selected_assets else 'N/A'}")
        lines.append(f"- TTPs seleccionadas: {', '.join(selected_ttps) if selected_ttps else 'N/A'}")
        lines.append(f"- Confianzas seleccionadas: {', '.join(str(confidence) for confidence in selected_confidences) if selected_confidences else 'N/A'}")
    
    if metadata:
        lines.append("")
        lines.append(f"El reporte base fue generado en `{metadata['timestamp']}`.")

    lines.append("")
    lines.append("### Guia visual")
    lines.append("")
    lines.append(
        "La codificacion cromatica sigue la misma lectura operativa del dashboard: verde para mejora "
        "o riesgo bajo, amarillo para niveles intermedios, naranja para riesgo elevado y rojo para "
        "riesgo alto o empeoramiento."
    )
    lines.append("")
    lines.append("| Color | Interpretacion |")
    lines.append("| --- | --- |")
    lines.append('| <span style="color:#2ECC71"><strong>Verde</strong></span> | Mejora, reduccion de riesgo o nivel bajo |')
    lines.append('| <span style="color:#F1C40F"><strong>Amarillo</strong></span> | Riesgo intermedio o cambio neutro |')
    lines.append('| <span style="color:#E67E22"><strong>Naranja</strong></span> | Riesgo elevado |')
    lines.append('| <span style="color:#E74C3C"><strong>Rojo</strong></span> | Riesgo alto o incremento de riesgo |')
    
    lines.append("")
    lines.append("### Riesgo global")
    lines.append("")
    lines.append(
        "La siguiente tabla resume el riesgo agregado del sistema para cada dimension CIA. "
        "Estos valores permiten identificar si la exposicion principal se concentra en "
        "confidencialidad, integridad o disponibilidad."
    )
    lines.append("")
    lines.append("| Dimension | Riesgo |")
    lines.append("| --- | ---: |")
    lines.append(f"| Confidencialidad | {format_risk_value(global_system_risk['confidentiality_risk'])} |")
    lines.append(f"| Integridad | {format_risk_value(global_system_risk['integrity_risk'])} |")
    lines.append(f"| Disponibilidad | {format_risk_value(global_system_risk['availability_risk'])} |")
    lines.append(f"| Riesgo medio | {format_risk_value(global_system_risk['overall_risk'])} |")

    if optimization_comparison:
        lines.append("")
        lines.append("### Comparativa de riesgo tras optimizacion")
        lines.append("")
        lines.append(
            "La siguiente comparativa resume el cambio estimado al aplicar la solucion de contramedidas. "
            "Los valores posteriores se calculan ponderando las decisiones optimizadas por la criticidad "
            "de los activos afectados, siguiendo el mismo criterio utilizado en el dashboard."
        )
        lines.append("")
        lines.append("| Dimension | Antes | Despues | Delta |")
        lines.append("| --- | ---: | ---: | ---: |")
        dimension_labels = {
            "global": "Riesgo medio",
            "confidentiality": "Confidencialidad",
            "integrity": "Integridad",
            "availability": "Disponibilidad",
        }
        for dimension in ["global", "confidentiality", "integrity", "availability"]:
            before = optimization_comparison["risk_before"][dimension]
            after = optimization_comparison["risk_after"][dimension]
            delta = after - before
            lines.append(
                f"| {dimension_labels[dimension]} | {format_risk_value(before)} | "
                f"{format_risk_value(after)} | {format_delta_value(delta)} |"
            )
    
    lines.append("")
    lines.append("### Amenazas analizadas")
    lines.append("")
    lines.append(
        "A continuacion se detallan las tecnicas ATT&CK consideradas en la ejecucion, junto con "
        "el activo inicial afectado, la confianza asignada y la tactica asociada."
    )
    lines.append("")
    
    if threat_vectors:
        lines.append("| TTP | Nombre | Activo | Confianza | Tactica |")
        lines.append("| --- | --- | --- | ---: | --- |")
        for ttp, threat_info in threat_vectors.items():
            lines.append(
                f"| {ttp} | {threat_info['name']} | {threat_info['asset']} | "
                f"{format_number(threat_info['confidence'])} | {threat_info['tactic']} |"
            )
    else:
        lines.append("No se han encontrado amenazas en el JSON de reporte.")
    
    lines.append("")
    lines.append("### Activos con mayor riesgo")
    lines.append("")
    lines.append(
        "La priorizacion de activos se ha realizado a partir del riesgo medio calculado para cada nodo. "
        "La tabla muestra los activos con mayor exposicion relativa dentro de la ejecucion analizada."
    )
    lines.append("")
    
    if nodes_risk:
        lines.append("| Activo | Nombre | Riesgo medio | C | I | A |")
        lines.append("| --- | --- | ---: | ---: | ---: | ---: |")
        for asset_id, asset_name, average_risk, c_risk, i_risk, a_risk in nodes_risk[:5]:
            lines.append(
                f"| {asset_id} | {asset_name} | {format_number(average_risk)} | "
                f"{format_number(c_risk)} | {format_number(i_risk)} | {format_number(a_risk)} |"
            )
    else:
        lines.append("No se han encontrado activos analizados en el JSON de reporte.")
    
    lines.append("")
    lines.append("### Optimizacion")
    lines.append("")
    
    if optimization_result:
        lines.append(
            f"El objetivo optimizado ha sido `{optimization_objective}`. La solucion obtenida identifica "
            "un conjunto de contramedidas candidatas que reducen el riesgo estimado respetando las "
            "restricciones de presupuesto y tiempo configuradas."
        )
        lines.append("")
        lines.append(f"- Estado del solver: {optimization_result['status']}")
        lines.append(f"- Riesgo base: {format_number(optimization_result['baseline_risk'])}")
        lines.append(f"- Riesgo optimizado normalizado: {format_number(optimization_result['optimal_risk_normalized'])}")
        lines.append(f"- Reduccion de riesgo: {format_number(optimization_result['risk_reduction'])}")
        lines.append(f"- Presupuesto disponible: {format_number(optimization_result['budget'])}")
        lines.append(f"- Coste total: {format_number(optimization_result['total_cost'])}")
        lines.append(f"- Porcentaje de presupuesto usado: {optimization_result['total_cost_used_percent']}")
        
        assets_decisions = optimization_result["assets_decisions"]
        if assets_decisions:
            report_assets = get_report_assets(reports_json)
            baseline_key_by_objective = {
                "global": "asset_average_risk",
                "confidentiality": "asset_confidentiality_risk",
                "integrity": "asset_integrity_risk",
                "availability": "asset_availability_risk",
            }
            solution_key_by_objective = {
                "global": "risk_total",
                "confidentiality": "asset_risk_C",
                "integrity": "asset_risk_I",
                "availability": "asset_risk_A",
            }
            baseline_metric = baseline_key_by_objective.get(optimization_objective, "asset_average_risk")
            optimized_metric = solution_key_by_objective.get(optimization_objective, "risk_total")

            lines.append("")
            lines.append(
                "Las decisiones recomendadas por activo se resumen en la siguiente tabla. Para cada activo "
                "se indica la contramedida seleccionada, el riesgo antes y despues para el objetivo optimizado, "
                "el delta resultante, el coste y el tiempo estimado de despliegue."
            )
            lines.append("")
            lines.append("| Activo | Nombre | Contramedida | Antes | Despues | Delta | Coste | Tiempo |")
            lines.append("| --- | --- | --- | ---: | ---: | ---: | ---: | ---: |")
            for asset_id, decision in assets_decisions.items():
                asset_info = report_assets.get(asset_id, {})
                asset_name = asset_info.get("node_data", {}).get("name", "Unknown")
                before_risk = float(asset_info.get(baseline_metric, 0.0) or 0.0)
                after_risk = float(decision.get(optimized_metric, 0.0) or 0.0)
                delta_risk = after_risk - before_risk
                lines.append(
                    f"| {asset_id} | {asset_name} | {decision['countermeasure']} | "
                    f"{format_risk_value(before_risk)} | {format_risk_value(after_risk)} | "
                    f"{format_delta_value(delta_risk)} | {format_number(decision['cost'])} | "
                    f"{format_number(decision['time_hours'])} h |"
                )
    else:
        lines.append("No se ha encontrado una solucion de optimizacion generada para esta ejecucion.")
    
    markdown_report = "\n".join(str(line) for line in lines)
    
    # Se escribe el informe generado en la ruta de salida indicada
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(markdown_report)
    
    return markdown_report
