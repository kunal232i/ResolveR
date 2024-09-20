import socket
import struct
import dns.resolver
import dns.rdatatype


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
        # extracts the domain name
        domain_name.append(buf[offset + 1:offset + 1 + length].decode())
        offset += length + 1

    domain_name = '.'.join(domain_name)
    qtype, qclass = struct.unpack("!HH", buf[offset:offset + 4])
    offset += 4

    question_section_bytes = buf[12:offset]

    return domain_name, qtype, qclass, question_section_bytes

def resolve_domain(domain_name, qtype):
    try:
        # using DNS resolver
        answers = dns.resolver.resolve(domain_name, dns.rdatatype.to_text(qtype))
        return answers
    except dns.resolver.NXDOMAIN:
        return None
    except dns.resolver.NoAnswer:
        return None
def construct_answer_section(domain_name, qtype, qclass, answers):
    answer_section = b""

    if answers:
        # Get the RRset for the answer
        rrset = answers.rrset
        packed_name = rrset.name.to_wire()  # Get the packed name from the RRset
        ttl = rrset.ttl  # Get the TTL from the RRset
        # Iterate through each rdata in the RRset
        for rdata in rrset:
            rdata_wire = rdata.to_wire()  # Serialize the RDATA
            # Append the packed domain name, qtype, qclass, ttl, and length of RDATA
            answer_section += packed_name
            answer_section += struct.pack("!HHIH",
                                          qtype,        # Type (A = 1)
                                          qclass,       # Class (IN = 1)
                                          ttl,          # TTL from the RRset
                                          len(rdata_wire))  # Length of RDATA
            answer_section += rdata_wire

    return answer_section



def main():
    print("Logs from your program will appear here!")

    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind(("127.0.0.1", 2053))
    
    while True:
        try:
            # 512 is buffer size
            buf, source = udp_socket.recvfrom(512)
            print(f"Received data from {source}")

            header = buf[:12]
            header_info = struct.unpack("!6H", header)

            domain_name, qtype, qclass, question_section = parse_question_section(buf, 12)
            print(f"Domain Name: {domain_name}, Type: {qtype}, Class: {qclass}")

            answers = resolve_domain(domain_name, qtype)

            answer_section = construct_answer_section(domain_name, qtype, qclass, answers)

            # Prepare response header
            response_flags = 0x8180 if answers else 0x8183  # No such name if no answers
            ancount = len(answers) if answers else 0
            response_header = struct.pack("!6H", header_info[0], response_flags, 1, ancount, 0, 0)

            # Construct the response with the header and question section
            response = response_header + question_section + answer_section
    
            udp_socket.sendto(response, source)
            print(f'Sending responce of {len(response)} bytes')
        except Exception as e:
            print(f"Error receiving data: {e}")
            break


if __name__ == "__main__":
    main()
