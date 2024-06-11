import socket
from honeypot import logger

def start_honeypot():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(("0.0.0.0", 8080))
    server_socket.listen(5)
    
    while True:
        client_socket, addr = server_socket.accept()
        data = client_socket.recv(1024)
        logger.log_attack(addr[0], data.decode('utf-8'))
        client_socket.close()
