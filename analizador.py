import re
from collections import Counter
from datetime import datetime

class SecurityAnalyzer:
    def __init__(self):
        self.total_analizado = 0
        self.conteo_usuarios = Counter()
        self.alertas = []
        # Lista de IDs que este motor puede procesar
        self.ids_criticos = [
            "4624", "4625", "4648", "4688", "4697", "4698", 
            "4702", "4719", "4720", "4724", "4728", "4732", "4740", 
            "4946", "4950", "5025", "5140", "1102", "6006"
        ]

    def extraer_campo(self, patron, texto):
        match = re.search(patron, texto, re.I | re.DOTALL)
        return match.group(1).strip() if match else "N/A"

    def procesar_linea(self, linea):
        parts = linea.split('\t')
        if len(parts) < 6: return
        
        self.total_analizado += 1
        fecha, eid, mensaje = parts[1], parts[3], parts[5]

        # Extraer usuario para estadísticas
        user = self.extraer_campo(r"Nombre de cuenta:\s+([^\n\r\t]+)", mensaje)
        if user != "N/A" and user.upper() not in ["SYSTEM", "SISTEMA", "-"]:
            self.conteo_usuarios[user] += 1

        # Filtrar solo IDs de seguridad relevantes
        if eid in self.ids_criticos:
            self.evaluar_amenaza(eid, mensaje, fecha, user)

    def evaluar_amenaza(self, eid, msg, fecha, user):
        """Lógica específica para cada uno de los 20 eventos clave"""
        
        # 1. Evasión: Borrado de Logs
        if eid == "1102":
            self.agregar_alerta("CRÍTICO", "Limpieza de Registro de Auditoría", "Un usuario intentó borrar sus huellas.", fecha, user)
        
        # 2. Persistencia: Nuevo Servicio
        elif eid == "4697":
            serv = self.extraer_campo(r"Nombre del servicio:\s+([^\n\r\t]+)", msg)
            self.agregar_alerta("ALTO", "Instalación de Nuevo Servicio", f"Servicio detectado: {serv}. Posible persistencia de malware.", fecha, user)
        
        # 3. Persistencia: Tarea Programada
        elif eid == "4698":
            task = self.extraer_campo(r"Nombre de la tarea:\s+([^\n\r\t]+)", msg)
            self.agregar_alerta("ALTO", "Creación de Tarea Programada", f"Tarea: {task}. Común en ataques planificados.", fecha, user)

        # 4. Fuerza Bruta: Fallo de Login
        elif eid == "4625":
            self.agregar_alerta("MEDIO", "Fallo de Inicio de Sesión", "Intento de acceso fallido.", fecha, user)

        # 5. Escalación: Usuario Agregado a Grupo Admin
        elif eid in ["4728", "4732"]:
            grupo = self.extraer_campo(r"Nombre del grupo:\s+([^\n\r\t]+)", msg)
            if "ADMIN" in grupo.upper():
                self.agregar_alerta("CRÍTICO", "Elevación de Privilegios", f"Usuario agregado al grupo: {grupo}", fecha, user)

        # 6. Evasión: Firewall Detenido
        elif eid == "5025":
            self.agregar_alerta("CRÍTICO", "Firewall de Windows Detenido", "El servicio de firewall fue desactivado.", fecha, user)

        # 7. Evasión: Cambio en Políticas de Auditoría
        elif eid == "4719":
            self.agregar_alerta("ALTO", "Cambio en Política de Seguridad", "Se modificó qué eventos se graban (intento de ocultamiento).", fecha, user)

        # 8. Movimiento Lateral: RDP o Red
        elif eid == "4624":
            tipo_logon = self.extraer_campo(r"Tipo de inicio de sesión:\s+(\d+)", msg)
            if tipo_logon == "10": # Remote Desktop
                self.agregar_alerta("INFORMATIVO", "Acceso por RDP", "Conexión remota exitosa.", fecha, user)
            elif tipo_logon == "3": # Network logon
                pass # Demasiado común, filtrar si es necesario

        # 9. Creación de Cuenta Backdoor
        elif eid == "4720":
            nueva_cta = self.extraer_campo(r"Nombre de cuenta:\s+([^\n\r\t]+)", msg)
            self.agregar_alerta("CRÍTICO", "Creación de Cuenta Nueva", f"Cuenta creada: {nueva_cta}", fecha, user)

        # 10. Bloqueo de Cuenta
        elif eid == "4740":
            self.agregar_alerta("ALTO", "Cuenta Bloqueada", "Posible ataque de Spraying o Fuerza Bruta masivo.", fecha, user)

        # 11. Ejecución de Procesos (Detección de comandos peligrosos)
        elif eid == "4688":
            cmd = self.extraer_campo(r"Línea de comandos de proceso:\s+([^\n\r\t]+)", msg)
            if any(x in cmd.lower() for x in ["powershell", "encodedcommand", "vssadmin", "whoami"]):
                self.agregar_alerta("ALTO", "Ejecución de Comando Sospechoso", f"Comando: {cmd[:50]}...", fecha, user)

        # 12. Modificación de Tareas
        elif eid == "4702":
            self.agregar_alerta("MEDIO", "Modificación de Tarea Programada", "Se alteró una tarea existente.", fecha, user)

        # 13. Credenciales Explícitas (Uso de RunAs)
        elif eid == "4648":
            self.agregar_alerta("MEDIO", "Uso de Credenciales Explícitas", "Un proceso intentó usar otras credenciales.", fecha, user)

        # 15. Cambio de Contraseña por Admin
        elif eid == "4724":
            self.agregar_alerta("ALTO", "Reseteo de Contraseña", "Un usuario intentó cambiar la contraseña de otro.", fecha, user)

        # 16. Excepciones en Firewall
        elif eid == "4946":
            regla = self.extraer_campo(r"Nombre:\s+([^\n\r\t]+)", msg)
            self.agregar_alerta("MEDIO", "Excepción en Firewall Añadida", f"Regla: {regla}", fecha, user)

        # 17. Cambio en Regla de Firewall
        elif eid == "4950":
            self.agregar_alerta("MEDIO", "Cambio en Configuración de Firewall", "Se modificó una regla existente.", fecha, user)

        # 18. Acceso a Recursos de Red (Shares)
        elif eid == "5140":
            recurso = self.extraer_campo(r"Nombre de recurso compartido:\s+([^\n\r\t]+)", msg)
            if "$" in recurso: # Shares administrativos como C$
                self.agregar_alerta("ALTO", "Acceso a Carpeta Administrativa", f"Recurso: {recurso}", fecha, user)

        # 19. Apagado del Sistema
        elif eid == "6006":
            self.agregar_alerta("MEDIO", "Apagado del Registro de Eventos", "El sistema se está apagando.", fecha, user)

    def agregar_alerta(self, nivel, tipo, detalle, fecha, user):
        self.alertas.append({
            "nivel": nivel,
            "tipo": tipo,
            "detalle": detalle,
            "fecha": fecha,
            "user": user
        })

def analizar_logs_detallado(archivo_path):
    analyzer = SecurityAnalyzer()
    
    try:
        with open(archivo_path, 'r', encoding="utf-16") as f:
            lineas = f.readlines()
    except:
        with open(archivo_path, 'r', encoding="utf-8", errors="ignore") as f:
            lineas = f.readlines()

    for linea in lineas:
        analyzer.procesar_linea(linea)

    return {
        "total": analyzer.total_analizado,
        "usuarios": dict(analyzer.conteo_usuarios.most_common(5)),
        "alertas": analyzer.alertas
    }