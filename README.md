# 🛡️ Windows-Security-Event-Analyzer
WSEA es un programa creado en Python para el análisis de logs de Windows, hecho para mostrar Indicadores de Compromiso (IoC) comunes. Procesa archivos .txt exportados del Visor de Eventos de Windows y genera reportes en PDF con niveles de severidad.

# 🚀 Capacidades de Detección

El analizador rastrea indicadores de compromiso comunes, dividiendolos por severidad, incluyendo:

    Persistencia: Creación de servicios (4697) y tareas programadas (4698).

    Evasión de Defensas: Borrado de logs de auditoría (1102) y desactivación de Firewall (5025).

    Escalada de Privilegios: Adición de usuarios a grupos administrativos (4732/4728).

    Fuerza Bruta: Monitoreo de fallos de inicio de sesión masivos (4625).

    Ejecución Sospechosa: Comandos de PowerShell, vssadmin (Ransomware) y herramientas de hacking.

# 🛠️ Estructura del Proyecto

    main.py: Orquestador principal del programa.

    analizador.py: Motor de lógica de seguridad y filtrado de ruido.

    reporte_pdf.py: Generador de informes visuales con clasificación (Crítico, Alto, Medio).

    generador.py: Codigo que da un .txt aleatorio con logs para probar el programa.

# 📖 Dependencias

    repositorio:
    git clone https://github.com/tu-usuario/Log-Analyzer.git
    dependencias:
    pip install fpdf
    Genera logs de prueba con:
    Python generador.py 
    o coloca tu archivo .txt en la raíz.

# 💻 Ejemplo de Uso y Salida:
    C:\Users\xxxxxxxx\Desktop\Log-Analyzer>python main.py
    Introduce el nombre del archivo a analizar (formato = .txt): logs.txt
    ==================================================
    ANALISIS DE VULNERABILIDADES - INICIO
    ==================================================
    [*] Analizando eventos de seguridad en: logs.txt...
    [*] Analisis completado. Total lineas: 5001
    [*] Amenazas encontradas: 214
    [*] Generando reporte PDF...

    [OK] Reporte generado con exito: Reporte_Analisis_Logs.pdf
    ==================================================
    PROCESO FINALIZADO CON EXITO
    ==================================================

    C:\Users\xxxxxxxx\Desktop\Log-Analyzer>

 <img width="780" height="875" alt="imagen" src="https://github.com/user-attachments/assets/3972e648-fc7d-4bba-9296-6af1899d6d8b" />
 
 Este es un ejemplo de lo que veriamos luego en nuestro pdf, dependiendo la cantidad de eventos y alertas que se detecten puede tener mas o menos paginas

# 🤝 Contribuciones y Contacto
¡Gracias por leerme! Este es uno de mis primeros proyectos, así que si el programa te sirve, te resulta interesante o tenés alguna idea para mejorarlo, sentite libre de clonarlo y probarlo!

Si te gustó, dale una ⭐ al repositorio, que sin duda ayuda.
