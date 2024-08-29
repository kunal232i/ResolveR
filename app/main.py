import socket
import struct


def parse_question_section(buf, offset):
    """
    Parse the question section of the DNS query.
    :param buf: The byte buffer containing the DNS query.
    :param offset: The offset where the question section starts.
    :return: (domain_name, qtype, qclass, question_section_bytes)
    """
    domain_name = []
    while True:
        length = buf[offset]
        if length == 0:
            offset += 1
            break
        domain_name.append(buf[offset + 1:offset + 1 + length].decode())
        offset += length + 1

    domain_name = '.'.join(domain_name)
    qtype, qclass = struct.unpack("!HH", buf[offset:offset + 4])
    offset += 4

    question_section_bytes = buf[12:offset]

    return domain_name, qtype, qclass, question_section_bytes


def main():
    print("Logs from your program will appear here!")

    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind(("127.0.0.1", 2053))
    
    while True:
        try:
            buf, source = udp_socket.recvfrom(512)
            print(f"Received data from {source}")

            header = buf[:12]
            header_info = struct.unpack("!6H", header)

            domain_name, qtype, qclass, question_section = parse_question_section(buf, 12)
            print(f"Domain Name: {domain_name}, Type: {qtype}, Class: {qclass}")

            # Prepare a response header (same Transaction ID and basic flags)
            response_header = struct.pack("!6H", header_info[0], 0x8180, 1, 0, 0, 0)

            # Construct the response with the header and question section
            response = response_header + question_section
    
            udp_socket.sendto(response, source)
            print(f'Sending: {response}')
        except Exception as e:
            print(f"Error receiving data: {e}")
            break


if __name__ == "__main__":
    main()
