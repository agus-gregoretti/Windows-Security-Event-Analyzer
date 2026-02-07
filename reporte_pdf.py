from fpdf import FPDF

class SecurityPDF(FPDF):
    def header(self):
        self.set_font("Arial", "B", 15)
        self.set_text_color(44, 62, 80)
        self.cell(0, 10, "INFORME ESTRATEGICO DE SEGURIDAD - WINDOWS AUDIT", ln=True, align="C")
        self.draw_line()
        self.ln(5)

    def draw_line(self):
        self.set_draw_color(44, 62, 80)
        self.line(10, 22, 200, 22)

    def chapter_title(self, title):
        self.set_font("Arial", "B", 12)
        self.set_fill_color(240, 240, 240)
        self.cell(0, 10, f" {title}", ln=True, fill=True)
        self.ln(2)

def generar_reporte_completo(datos, nombre_archivo):
    # Función interna para limpiar caracteres no soportables para PDF
    def clean(text):
        return str(text).encode('latin-1', 'replace').decode('latin-1')

    pdf = SecurityPDF()
    pdf.add_page()
    
    # --- SECCIÓN 1: RESUMEN ---
    pdf.chapter_title("1. RESUMEN DE ACTIVIDAD")
    pdf.set_font("Arial", "", 10)
    pdf.cell(0, 7, clean(f"Total de logs procesados: {datos['total']}"), ln=True)
    pdf.cell(0, 7, clean(f"Eventos de seguridad detectados: {len(datos['alertas'])}"), ln=True)
    pdf.ln(5)

    # --- SECCIÓN 2: TOP USUARIOS ---
    pdf.chapter_title("2. TOP USUARIOS ACTIVOS")
    for user, cant in datos['usuarios'].items():
        pdf.cell(0, 7, clean(f"   > {user}: {cant} eventos"), ln=True)
    pdf.ln(5)

    # --- SECCIÓN 3: ANALISIS DE AMENAZAS ---
    pdf.chapter_title("3. DETECCION DE VULNERABILIDADES Y EXPLOITS")
    
    if not datos['alertas']:
        pdf.set_font("Arial", "I", 10)
        pdf.cell(0, 10, "No se encontraron indicadores de compromiso (IoC).", ln=True)
    else:
        for alerta in datos['alertas']:
            # Color según severidad
            if alerta['nivel'] == "CRITICO":
                pdf.set_text_color(192, 57, 43)
            elif alerta['nivel'] == "ALTO":
                pdf.set_text_color(211, 84, 0)
            elif alerta['nivel'] == "MEDIO":
                pdf.set_text_color(41, 128, 185)
            else:
                pdf.set_text_color(0, 0, 0)

            pdf.set_font("Arial", "B", 11)
            pdf.cell(0, 8, clean(f"[{alerta['nivel']}] {alerta['tipo']}"), ln=True)
            
            pdf.set_text_color(0, 0, 0)
            pdf.set_font("Arial", "", 9)
            pdf.multi_cell(0, 5, clean(f"    Fecha: {alerta['fecha']} | Usuario: {alerta['user']}\n    Detalle: {alerta['detalle']}"))
            pdf.ln(3)

    try:
        pdf.output(nombre_archivo)
        print(f"\n[OK] Reporte generado con exito: {nombre_archivo}")
    except Exception as e:
        print(f"\n[ERROR] Error al escribir el PDF: {e}")