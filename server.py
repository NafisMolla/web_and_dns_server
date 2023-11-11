# server.py
import socket
import random
import struct

# Predefined table of domain names and corresponding IP addresses
dns_table = {
    'google.com':  ["192.165.1.1", "192.165.1.10"],
    'youtube.com': ['192.165.1.2'],
    'uwaterloo.ca': ['192.165.1.3'],
    'wikipedia.org': ['192.165.1.4'],
    'amazon.ca': ['192.165.1.5'],
}

def format_bytes(data_str):
    """
    Takes a string of data and formats it to be spaced apart every 2 characters.
    
    Parameters:
    data_str (str): The string of data to be formatted.
    
    Returns:
    str: The formatted data string.
    """
    chunk_size = 2
    return ' '.join([data_str[i:i+chunk_size] for i in range(0, len(data_str), chunk_size)])


def build_dns_response(query_packet, queried_domain):
    tid = query_packet[:2]  # Retain the transaction ID from the incoming query
    header_flags = b'\x84\x00'  # Setup for standard response
    q_count = b'\x00\x01'  # One question in the query
    ans_count = struct.pack('>H', len(dns_table[queried_domain]))  # Number of answers
    auth_rr_count = b'\x00\x00'  # No authoritative records
    add_rr_count = b'\x00\x00'  # No additional records

    # Assemble the DNS packet header
    packet_header = tid + header_flags + q_count + ans_count + auth_rr_count + add_rr_count
    query_body_end = query_packet.find(b'\x00', 12) + 5
    query_section = query_packet[12:query_body_end]  # Extract the question section from the query
    dns_response = packet_header + query_section

    # Construct the answer section
    for ip_addr in dns_table[queried_domain]:
        resource_record = b'\xc0\x0c'  # Pointer to the domain name in the question section
        record_type = b'\x00\x01'  # Type A
        record_class = b'\x00\x01'  # Class IN
        time_to_live = struct.pack('>I', 260)  # Time To Live
        rdata_length = b'\x00\x04'  # Length of RDATA field
        resource_data = socket.inet_aton(ip_addr)  # The IP address in network byte order
        dns_response += resource_record + record_type + record_class + time_to_live + rdata_length + resource_data

    return dns_response


# Set up the server socket
server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server_socket.bind(('127.0.0.1', 10000))  # Use a port >1023 to not require superuser

print("DNS server is running...")

try:
    while True:
        # Receive DNS query
        message, address = server_socket.recvfrom(512)
        print(f"Request:\n{format_bytes(message.hex())}")
        
        query_id = struct.unpack('!H', message[:2])[0]
        domain_length = struct.unpack('!B', message[12:13])[0]
        domain = message[13:13+domain_length].decode().lower() 
        extension_length = struct.unpack('!B', message[13 + domain_length:14 + domain_length])[0]
        extension = message[14 + domain_length:14 + domain_length + extension_length].decode()
        

        # Check if the domain is in the table
        domain += "."
        domain += extension
        if domain in dns_table:
            # Create DNS response
            response = build_dns_response(message,domain)
            server_socket.sendto(response, address)

            # Display response message
            print(f"Response:\n{format_bytes(response.hex())}")
        else:
            print(f"Domain {domain} not found in DNS table.")

except KeyboardInterrupt:
    print("Shutting down the server...")
    server_socket.close()
