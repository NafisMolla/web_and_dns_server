# Client Code with output parsing and formatted display
import socket
import os
import struct
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

def create_dns_query(domain_name):
    transaction_id = os.urandom(2)  # Random transaction ID
    flags = b'\x01\x00'  # QR=0, OPCODE=0, AA=0, TC=0, RD=1, RA=0, Z=0, RCODE=0
    questions = b'\x00\x01'  # QDCOUNT=1
    answer_rrs = b'\x00\x00'  # ANCOUNT=0
    authority_rrs = b'\x00\x00'  # NSCOUNT=0
    additional_rrs = b'\x00\x00'  # ARCOUNT=0

    # Create question field
    domain_parts = domain_name.split('.')
    question = b''
    for part in domain_parts:
        question += bytes([len(part)]) + part.encode()
    question += b'\x00'  # End of the domain name

    # Type and class for the question
    qtype = b'\x00\x01'  # Type A
    qclass = b'\x00\x01'  # Class IN

    return transaction_id + flags + questions + answer_rrs + authority_rrs + additional_rrs + question + qtype + qclass



def parse_dns_response(response):
        # Skip the header and the question sections.
    header_length = 12
    pos = header_length
    while response[pos] != 0:
        pos += 1
    pos += 5  # Skip the null byte at the end of the domain, QTYPE, and QCLASS.

    # Number of answers
    ancount = struct.unpack('!H', response[6:8])[0]

    ips = []
    for _ in range(ancount):
        # Skip the name (which is a pointer here)
        pos += 2

        # TYPE, CLASS, TTL, RDLENGTH
        _, _, _, rdlength = struct.unpack('!HHIH', response[pos:pos+10])
        pos += 10

        # RDATA
        rdata = response[pos:pos+rdlength]
        pos += rdlength

        # If it's an IPv4 address, it will have a length of 4 bytes
        if rdlength == 4:
            ip_address = socket.inet_ntoa(rdata)
            ips.append(ip_address)

    return ips

def parse_dns_response2(response):
    # Unpack the header
    header = struct.unpack('!6H', response[:12])
    query_id, flags, qdcount, ancount, nscount, arcount = header

    # Skip the query section
    pos = 12
    for _ in range(qdcount):
        while response[pos] != 0:  # Look for the null byte indicating the end of the domain name
            pos += 1
        pos += 5  # Skip the null byte, QTYPE, and QCLASS

    # Process the answer section
    records = []
    for _ in range(ancount):
        # Name field (a pointer in this case)
        name, = struct.unpack('!H', response[pos:pos+2])
        pos += 2
        
        # TYPE, CLASS, TTL, RDLENGTH
        type_code, class_code, ttl, rdlength = struct.unpack('!2HLH', response[pos:pos+10])
        pos += 10
        
        # RDATA
        rdata = response[pos:pos+rdlength]
        pos += rdlength

        if type_code == 1 and class_code == 1:  # If it's an A record and IN class
            ip_address = socket.inet_ntoa(rdata)
            records.append((name, type_code, class_code, ttl, rdlength, ip_address))
    
    return records
    
def extract_ips_from_dns_response(dns_response_hex):
    """
    Extracts all IP addresses from a DNS response.

    Parameters:
    dns_response_hex (str): A string containing the hex representation of the DNS response.

    Returns:
    list: A list of IP addresses extracted from the DNS response.
    """
    # Convert the hex string into bytes for easier manipulation
    dns_response_bytes = bytes.fromhex(dns_response_hex.replace(" ", ""))

    # The header is 12 bytes long, we can skip the question section by finding the end of it
    # The question ends with 00 which signifies the root label of the domain name system
    # and after that, it is followed by QTYPE and QCLASS which are 4 bytes in total
    end_of_question = dns_response_bytes.find(b'\x00', 12) + 5  # +1 for the 00 byte itself and +4 for QTYPE and QCLASS

    # Extract the number of answers from the header
    ancount = int.from_bytes(dns_response_bytes[6:8], byteorder='big')

    # Initialize the list to hold IP addresses
    ip_addresses = []

    # The Answer section starts after the end of the question section
    current_position = end_of_question
    for _ in range(ancount):
        # The NAME field is a pointer (2 bytes), followed by TYPE (2 bytes), CLASS (2 bytes),
        # TTL (4 bytes), RDLENGTH (2 bytes), and finally RDATA (4 bytes for IP addresses)
        # Skip to the RDATA field which is 12 bytes from the start of the answer record
        rdata_position = current_position + 12
        # Extract the IP address and add it to the list
        ip_address = dns_response_bytes[rdata_position:rdata_position + 4]
        ip_addresses.append(".".join(str(b) for b in ip_address))

        # Move to the next record which is 16 bytes away
        current_position += 16

    return ip_addresses



def run_dns_client_formatted(server_ip, port=10000):  # DNS typically uses port 53
    # Create a UDP socket
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client_socket:
        while True:
            # Take domain name input from user
            domain_name = input("Enter Domain Name (or 'exit' to quit): ")
            # Conditional statement to exit
            if domain_name.lower() == 'exit':
                print("Client exiting.")
                break

            # Send the domain name as the DNS query to the server
            dns_query = create_dns_query(domain_name)
            client_socket.sendto(dns_query, (server_ip, port))

            # Receive the response from the server
            response, _ = client_socket.recvfrom(512)
            
            print(response)
            
            formatted_response = format_bytes(response.hex())
            
            print(formatted_response)
            
            hex_string_without_spaces = formatted_response.replace(" ", "")
            # Parse response
            ip_address = extract_ips_from_dns_response(hex_string_without_spaces)
            print(ip_address)
            
            for ip in ip_address:
                print(f"> {domain_name}: type A, class IN, TTL 260, addr (4) {ip}")
            
            

# Uncomment the line below to run the client when ready
run_dns_client_formatted('127.0.0.1')  # Replace '127.0.0.1' with your server's IP address when running the client
