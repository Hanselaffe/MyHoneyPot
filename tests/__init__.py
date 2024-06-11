import socket

def test_honeypot():
    server_address = ('localhost', 8080)
    test_data = "This is a test"

    # Create a TCP/IP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        # Connect to the server
        sock.connect(server_address)

        # Send data
        sock.sendall(test_data.encode('utf-8'))

        # Look for the response
        response = sock.recv(1024)
        print(f"Received: {response.decode('utf-8')}")

    finally:
        sock.close()

if __name__ == "__main__":
    test_honeypot()
