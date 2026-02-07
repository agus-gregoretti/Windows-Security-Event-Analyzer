import random
from datetime import datetime, timedelta

def generar_logs_variables(nombre_archivo="logs.txt", num_eventos=5000):
    usuarios_victimas = ["User-Martin\\martin", "ADMINISTRADOR", "INVITADO", "SOPORTE_TI"]
    procesos_maliciosos = ["powershell.exe -enc Zm9vYmFy", "vssadmin.exe delete shadows /all", "nc.exe -lvp 4444", "mimikatz.exe"]
    servicios_raros = ["UpdaterService", "WinDefendUpdate", "SystemBackupCheck"]
    
    ids_interes = ["4624", "4625", "4648", "4672", "4688", "4697", "4698", "1102", "4732", "4720"]
    
    start_time = datetime.now() - timedelta(days=1)
    
    print(f"[*] Iniciando generacion de {num_eventos} eventos...")

    with open(nombre_archivo, "w", encoding="utf-16") as f:
        
        f.write("Palabras clave\tFecha y hora\tOrigen\tId. del evento\tCategoría de la tarea\tMensaje\n")
        
        for i in range(num_eventos):
            current_time = start_time + timedelta(seconds=i * random.randint(1, 5))
            fecha_str = current_time.strftime("%d/%m/%Y %H:%M:%S")
            
            # Probabilidad de evento critico vs ruido
            es_ataque = random.random() < 0.08 
            eid = random.choice(ids_interes) if es_ataque else random.choice(["5058", "5061", "4624", "4672"])
            user = random.choice(usuarios_victimas)
            
            # Mensajes
            if eid == "4625":
                msg = f"Fallo de inicio de sesión.\r\n\r\nSujeto:\r\n\tNombre de cuenta:\t\t{user}\r\n\tCódigo de error:\t\t0xC000006D"
            
            elif eid == "4688":
                cmd = random.choice(procesos_maliciosos) if es_ataque else "chrome.exe"
                msg = f"Se creó un nuevo proceso.\r\n\r\nInformación del proceso:\r\n\tNombre de cuenta:\t\t{user}\r\n\tLínea de comandos de proceso:\t\t{cmd}"
            
            elif eid == "4697":
                serv = random.choice(servicios_raros)
                msg = f"Se instaló un servicio en el sistema.\r\n\r\nInformación del servicio:\r\n\tNombre del servicio:\t\t{serv}\r\n\tNombre del archivo:\t\tC:\\Temp\\{serv}.exe"
            
            elif eid == "1102":
                msg = f"Se borró el registro de auditoría.\r\n\r\nSujeto:\r\n\tNombre de cuenta:\t\t{user}"
            
            elif eid == "4732":
                msg = f"Se agregó un miembro a un grupo local.\r\n\r\nMiembro:\r\n\tNombre de cuenta:\t\t{user}\r\n\tNombre del grupo:\t\tAdministradores"
            
            elif eid == "4672":
                msg = f"Se asignaron privilegios especiales.\r\n\r\nSujeto:\r\n\tNombre de cuenta:\t\t{user}\r\n\tPrivilegios:\t\tSeSecurityPrivilege"

            else:
                msg = f"Mensaje genérico del sistema.\r\n\r\nAsunto:\r\n\tNombre de cuenta:\t\t{user}"

            # Escribir con formato de tabulaciones real
            f.write(f"Auditoría correcta\t{fecha_str}\tMicrosoft-Windows-Security-Auditing\t{eid}\tSeguridad\t\"{msg}\"\n")

    print(f"✅ Generado archivo '{nombre_archivo}' con {num_eventos} eventos variables.")

if __name__ == "__main__":
    generar_logs_variables()