# Adjusting the function to interpret the bytes in the order they appear in the DNS response
def extract_ips_from_dns_response_standard_order(dns_response_hex):
    """
    Extracts all IP addresses from a DNS response, interpreting the bytes in the order they appear.

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



hex_string_with_spaces = "26 8c 84 00 00 01 00 02 00 00 00 00 01 00 00 01 00 00 00 00 00 00 06 67 6f 6f 67 6c 65 03 63 6f 6d 00 c0 0c 00 01 00 01 00 00 01 04 00 04 c0 a5 01 01 c0 0c 00 01 00 01 00 00 01 04 00 04 c0 a5 01 0a"

hex_string_without_spaces = hex_string_with_spaces.replace(" ", "")

ip = extract_ips_from_dns_response_standard_order(hex_string_with_spaces)

print(ip)