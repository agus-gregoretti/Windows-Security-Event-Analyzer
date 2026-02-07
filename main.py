import analizador
import reporte_pdf
import os

def main():
    # Nombre del archivo de entrada y salida
    archivo_logs = input("Introduce el nombre del archivo a analizar (formato = .txt): ")
    nombre_reporte = "Reporte_Analisis_Logs.pdf"

    print("="*50)
    print("ANALISIS DE VULNERABILIDADES - INICIO")
    print("="*50)

    # Verificamos si existe el archivo de logs
    if not os.path.exists(archivo_logs):
        print(f"[!] Error: No se encuentra el archivo '{archivo_logs}'")
        print("Asegurate de que los logs esten en la misma carpeta que este script.")
        return

    print(f"[*] Analizando eventos de seguridad en: {archivo_logs}...")
    
    # 1. Llamada al analizador
    resultados = analizador.analizar_logs_detallado(archivo_logs)

    # 2. Resumen rápido por consola
    print(f"[*] Analisis completado. Total lineas: {resultados['total']}")
    print(f"[*] Amenazas encontradas: {len(resultados['alertas'])}")

    # 3. Generacion del PDF
    print(f"[*] Generando reporte PDF...")
    reporte_pdf.generar_reporte_completo(resultados, nombre_reporte)

    print("="*50)
    print("PROCESO FINALIZADO CON EXITO")
    print("="*50)

if __name__ == "__main__":
    main()