"""
Welcome Screen de CARE: Bienvenida profesional y elegante al motor de análisis cibernético.
Siguiendo el estilo y patrones visuales del dashboard principal.
"""

#==============================================[IMPORTS]==============================================#
from rich.console import Console
from rich.text import Text


#==============================================[CONSTANTES]==============================================#

CARE_BANNER = r"""
 ██████╗  █████╗ ██████╗ ███████╗
██╔════╝ ██╔══██╗██╔══██╗██╔════╝
██║      ███████║██████╔╝█████╗
██║      ██╔══██║██╔══██╗██╔══╝
╚██████╗ ██║  ██║██║  ██║███████╗
 ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝
"""

SYSTEM_DIVIDER = "─" * 72


#==============================================[CONSOLE_Y_RENDERIZADO]==============================================#

console = Console()


def render_welcome_screen():
    """
    Renderiza la pantalla de bienvenida completa de CARE.

    Presenta el banner ASCII, la identidad del sistema, sus capacidades
    principales y el estado final de inicialización en un formato
    profesional y sobrio.
    """
    console.clear()

    # Banner principal
    banner_text = Text(CARE_BANNER, style="bold cyan", justify="center")
    console.print(banner_text)

    # Nombre expandido y tagline
    title = Text(justify="center")
    title.append("Cyber Action Recommendation Engine\n", style="bold white")
    title.append("Advanced Decision Support for Cyber Defense Operations", style="dim cyan")
    console.print(title)
    console.print()

    # Separador superior
    divider = Text(SYSTEM_DIVIDER, style="dim cyan", justify="center")
    console.print(divider)
    console.print()

    # Descripción breve y más contundente
    description = Text(justify="center")
    description.append(
        "CARE is an advanced decision-support system for cyber defense operations.\n",
        style="white",
    )
    description.append(
        "It analyzes threats, evaluates risk propagation, and recommends\n",
        style="white",
    )
    description.append(
        "optimal countermeasures across complex infrastructures.",
        style="white",
    )
    console.print(description)
    console.print()

    # Capacidades
    capabilities_header = Text("Core Capabilities", style="bold bright_white", justify="center")
    console.print(capabilities_header)
    console.print()

    capabilities = [
        "Threat vector analysis",
        "Asset exposure assessment",
        "CIA risk evaluation",
        "Countermeasure optimization",
    ]

    for capability in capabilities:
        cap_line = Text(f"  • {capability}", style="white", justify="center")
        console.print(cap_line)

    console.print()
    console.print(divider)
    console.print()

    # Estado del sistema
    status = Text(justify="center")
    status.append("System initialized. ", style="white")
    status.append("Awaiting operator command.", style="bold green")
    console.print(status)
    console.print()

    # Prompt final
    prompt = Text("> _", style="bold cyan", justify="center")
    console.print(prompt)


def main():
    """
    Función principal de la welcome screen.

    Inicializa y renderiza la interfaz de bienvenida de CARE.
    """
    render_welcome_screen()


if __name__ == "__main__":
    main()