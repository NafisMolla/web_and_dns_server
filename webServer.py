import socket
import os
from datetime import datetime
import mimetypes
import urllib.parse

# Define the server's IP address and port
host = '127.0.0.1'  # localhost - the server will run on the local machine
port = 6780  # The port that the server will listen on, can be changed if needed

# Create a socket object using IPv4 (AF_INET) and TCP protocol (SOCK_STREAM)
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Set the socket option to allow the server to reuse the address (helpful for avoiding the "address already in use" error)
server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

# Bind the socket to the address and port specified above
server_socket.bind((host, port))

# Start listening for incoming connections with a backlog of 5 (max 5 connections in the waiting queue)
server_socket.listen(5)
print(f"Server is running on http://{host}:{port}")

def generate_headers(code, file_path):
    header = ''  # Initialize an empty string for headers
    # Add an HTTP status line to the header based on the response code
    if code == 200:
        header += 'HTTP/1.1 200 OK\n'
        # Determine the MIME type of the file and add a Content-Type header
        content_type = mimetypes.guess_type(file_path)[0] or 'text/html'
        header += f'Content-Type: {content_type}\n'
        # Add a Content-Length header with the size of the file
        header += f'Content-Length: {os.path.getsize(file_path)}\n'
    elif code == 404:
        header += 'HTTP/1.1 404 Not Found\n'  # Status line for a 404 response

    # Add the current date and time in the HTTP date format
    header += f'Date: {datetime.now().strftime("%a, %d %b %Y %H:%M:%S GMT")}\n'
    # Server name/version header
    header += 'Server: Simple-Python-Server\n'
    # Last modified time of the requested file
    header += f'Last-Modified: {datetime.fromtimestamp(os.path.getmtime(file_path)).strftime("%a, %d %b %Y %H:%M:%S GMT")}\n'
    # Keep the connection alive
    header += 'Connection: keep-alive\n\n'  # End of header sections

    return header

def handle_request(client_socket):
    client_socket.settimeout(5.0)  # Set a timeout for the client connection of 5 seconds

    while True:
        try:
            # Receive the request from the client, up to 1024 bytes
            request = client_socket.recv(1024).decode()
            if not request:
                break  # If no data is received, break the loop and close the connection

            print(request)
            lines = request.split('\n')  # Split the request into lines
            filename = lines[0].split()[1]  # Parse the requested filename from the request line

            # Decode URL-encoded characters in the filename
            filename = urllib.parse.unquote(filename)

            # If the filename starts with a '/', remove it to get the file path
            if filename.startswith('/'):
                filename = filename[1:]

            # If no filename is provided, default to 'HelloWorld.html'
            if not filename:
                filename = 'HelloWorld.html'

            # If the file exists, generate appropriate headers and read the file content
            if os.path.exists(filename):
                header = generate_headers(200, filename)
                response = header.encode()

                # If it's a GET request, read the file content and append it to the response
                if 'GET' in lines[0]:
                    with open(filename, 'rb') as file:
                        response += file.read()
            else:
                # If the file doesn't exist, send a 404 response with a custom 404 page
                default_404_file = 'error404.html'  # Default file to serve if the requested file is not found
                header = generate_headers(404, default_404_file)
                response = header.encode()

                if 'GET' in lines[0]:
                    with open(default_404_file, 'rb') as file:
                        response += file.read()

            # Send the response to the client
            client_socket.sendall(response)
        except socket.timeout:
            break  # If a timeout occurs, break the loop and close the connection
        except Exception as e:
            print(f"Error occurred: {e}")
            break

    client_socket.close()  # Close the client socket after serving the request or on timeout/error

while True:
    # Wait for a new client to connect
    client_socket, addr = server_socket.accept()
    print(f"Got a connection from {addr}")

    # Handle the client's request
    handle_request(client_socket)
