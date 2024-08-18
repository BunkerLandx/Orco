import socket
from threading import Thread, Lock
from queue import Queue
import ipaddress
import time
import os

class EscanerPuertos:
    def __init__(self, ip_range="0.0.0.0/0", port_range=(1, 65535), max_threads=1000, verbose=True):
        self.ip_range = ipaddress.ip_network(ip_range, strict=False)
        self.port_range = port_range
        self.max_threads = max_threads
        self.verbose = verbose
        self.lock = Lock()
        self.queue = Queue()
        self.resultados = {}
        self.archivo_log = f"resultados_escaneo_{time.strftime('%Y%m%d_%H%M%S')}.txt"

    def imprimir_verbose(self, mensaje):
        if self.verbose:
            print(mensaje)

    def escanear_puerto(self, ip, puerto):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1)
            try:
                resultado = sock.connect_ex((ip, puerto))
                if resultado == 0:
                    with self.lock:
                        if ip not in self.resultados:
                            self.resultados[ip] = []
                        self.resultados[ip].append(puerto)
                    self.imprimir_verbose(f"Puerto {puerto} abierto en {ip}")
            except socket.error:
                pass

    def trabajador(self):
        while not self.queue.empty():
            ip, puerto = self.queue.get()
            self.escanear_puerto(ip, puerto)
            self.queue.task_done()

    def generar_tareas(self):
        for ip in self.ip_range.hosts():
            for puerto in range(self.port_range[0], self.port_range[1] + 1):
                self.queue.put((str(ip), puerto))

    def validar_ip_range(self):
        try:
            ipaddress.ip_network(self.ip_range, strict=False)
            return True
        except ValueError as e:
            print(f"Error en el rango de IPs: {e}")
            return False

    def guardar_resultados(self):
        with open(self.archivo_log, 'w') as f:
            for ip, puertos in self.resultados.items():
                f.write(f"{ip}: {', '.join(map(str, puertos))}\n")
        print(f"Resultados guardados en {self.archivo_log}")

    def iniciar_escaneo(self):
        if not self.validar_ip_range():
            print("Rango de IPs inválido. Saliendo.")
            return
        
        print(f"Escaneando el rango de IPs: {self.ip_range}")
        print(f"Escaneando el rango de puertos: {self.port_range[0]}-{self.port_range[1]}")
        inicio = time.time()

        self.generar_tareas()

        hilos = []
        for _ in range(self.max_threads):
            hilo = Thread(target=self.trabajador)
            hilo.start()
            hilos.append(hilo)

        for hilo in hilos:
            hilo.join()

        self.queue.join()

        fin = time.time()
        print(f"Escaneo completado en {fin - inicio:.2f} segundos")
        self.guardar_resultados()

if __name__ == "__main__":
    ip_range = input("Ingrese el rango de IPs en formato CIDR (por ejemplo, 192.168.1.0/24): ").strip()
    port_range_start = int(input("Ingrese el puerto inicial (por ejemplo, 1): ").strip())
    port_range_end = int(input("Ingrese el puerto final (por ejemplo, 65535): ").strip())
    max_threads = int(input("Ingrese el número máximo de hilos (por ejemplo, 100): ").strip())
    verbose = input("¿Habilitar modo verbose? (s/n): ").strip().lower() == 's'

    escaner = EscanerPuertos(ip_range=ip_range, port_range=(port_range_start, port_range_end), max_threads=max_threads, verbose=verbose)
    escaner.iniciar_escaneo()
