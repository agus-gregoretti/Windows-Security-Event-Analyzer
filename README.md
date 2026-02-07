# 🛡️ Windows-Security-Event-Analyzer
WSEA es un programa creado en Python para el análisis de logs de Windows, hecho para mostrar Indicadores de Compromiso (IoC) comunes. Procesa archivos .txt exportados del Visor de Eventos de Windows y genera reportes en PDF con niveles de severidad.

# 🚀 Capacidades de Detección

El analizador rastrea los 20 eventos más críticos, incluyendo:

    Persistencia: Creación de servicios (4697) y tareas programadas (4698).

    Evasión de Defensas: Borrado de logs de auditoría (1102) y desactivación de Firewall (5025).

    Escalación de Privilegios: Adición de usuarios a grupos administrativos (4732/4728).

    Fuerza Bruta: Monitoreo de fallos de inicio de sesión masivos (4625).

    Ejecución Sospechosa: Comandos de PowerShell, vssadmin (Ransomware) y herramientas de hacking.

# 🛠️ Estructura del Proyecto

    main.py: Orquestador principal del flujo de trabajo.

    analizador.py: Motor de lógica de seguridad y filtrado de ruido.

    reporte_pdf.py: Generador de informes visuales con clasificación por colores (Crítico, Alto, Medio).

    generador.py: Simulador estocástico de logs para pruebas de estrés y validación de alertas.

# 📖 Instrucciones de Uso

    Clona el repositorio:
    Bash

    git clone https://github.com/tu-usuario/Log-Analyzer.git

    Instala las dependencias:
    Bash

    pip install fpdf

    Genera logs de prueba o coloca tu archivo logs.txt en la raíz.

    Ejecuta el análisis:
    Bash

    python main.py
