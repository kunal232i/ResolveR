import socket
import struct
import time
from collections import namedtuple
import logging
import random

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

# DNS header flags
QR_QUERY = 0x0000
QR_RESPONSE = 0x8000
AA = 0x0400
TC = 0x0200
RD = 0x0100
RA = 0x0080
Z = 0x0000
RCODE_NOERROR = 0x0000
RCODE_NXDOMAIN = 0x0003

# Record types
TYPE_A = 1
TYPE_NS = 2
TYPE_CNAME = 5
TYPE_SOA = 6
TYPE_PTR = 12
TYPE_MX = 15
TYPE_TXT = 16
TYPE_AAAA = 28

# Classes
CLASS_IN = 1

# Cache entry
CacheEntry = namedtuple('CacheEntry', ['data', 'expire_time'])

class DNSServer:
    def __init__(self, host='127.0.0.1', port=2053):
        self.host = host
        self.port = port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind((self.host, self.port))
        self.cache = {}

    def run(self):
        print(f"DNS Server running on {self.host}:{self.port}")
        while True:
            data, addr = self.socket.recvfrom(512)
            response = self.handle_query(data)
            self.socket.sendto(response, addr)

    def handle_query(self, data):
        header = DNSHeader.from_bytes(data[:12])
        question = DNSQuestion.from_bytes(data[12:])
        
        print(f"Received query for {question.qname}")

        # Check cache first
        cached_response = self.check_cache(question)
        if cached_response:
            print(f"Cache hit for {question.qname}")
            return self.build_response(header, question, cached_response)

        # If not in cache, perform recursive query
        print(f"Cache miss for {question.qname}, performing recursive query")
        full_response = self.recursive_query(question)
        
        if full_response:
            self.update_cache(question, full_response)
            return self.build_response(header, question, full_response)
        else:
            return self.build_error_response(header, question)

    def recursive_query(self, question):
        nameservers = ['198.41.0.4']  # a.root-servers.net
        while nameservers:
            for ns in nameservers:
                try:
                    response = self.query_dns_server(ns, question)
                    header = DNSHeader.from_bytes(response[:12])
                    
                    if header.ancount > 0:
                        # Extract the entire response, including answer, authority, and additional sections
                        return self.parse_full_response(response)
                    elif header.nscount > 0:
                        nameservers = self.extract_nameservers(response)
                        break
                    else:
                        return None
                except Exception as e:
                    print(f"Error querying {ns}: {e}")
            else:
                return None
        return None

    def parse_full_response(self, response):
        header = DNSHeader.from_bytes(response[:12])
        offset = 12  # Skip header
        
        # Skip question section
        _, offset = self.parse_name(response, offset)
        offset += 4  # Skip qtype and qclass
        
        answers = []
        for _ in range(header.ancount):
            rr, offset = self.parse_rr(response, offset)
            answers.append(rr)
        
        authorities = []
        for _ in range(header.nscount):
            rr, offset = self.parse_rr(response, offset)
            authorities.append(rr)
        
        additionals = []
        for _ in range(header.arcount):
            rr, offset = self.parse_rr(response, offset)
            additionals.append(rr)
        
        return (answers, authorities, additionals)

    def parse_rr(self, data, offset):
        name, offset = self.parse_name(data, offset)
        rrtype, rrclass, ttl, rdlength = struct.unpack('!HHIH', data[offset:offset+10])
        offset += 10
        rdata = data[offset:offset+rdlength]
        offset += rdlength
        return (name, rrtype, rrclass, ttl, rdlength, rdata), offset

    def extract_answer(self, response, question):
        offset = 12  # Skip header
        
        # Skip question section
        qname, offset = self.parse_name(response, offset)
        offset += 4  # Skip qtype and qclass
        
        # Parse answer section
        header = DNSHeader.from_bytes(response[:12])
        for _ in range(header.ancount):
            name, offset = self.parse_name(response, offset)
            rrtype, rrclass, ttl, rdlength = struct.unpack('!HHIH', response[offset:offset+10])
            offset += 10
            
            if rrtype == question.qtype:
                rdata = response[offset:offset+rdlength]
                return (name, rrtype, rrclass, ttl, rdlength, rdata)
            
            offset += rdlength
        
        return None

    def query_dns_server(self, ns, question):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(5)
        
        header = DNSHeader(rd=1)
        query = header.to_bytes() + question.to_bytes()
        
        sock.sendto(query, (ns, 53))
        response, _ = sock.recvfrom(512)
        return response

    def extract_nameservers(self, response):
        nameservers = []
        offset = 12  # Skip header
        
        # Skip question section
        qname, offset = self.parse_name(response, offset)
        offset += 4  # Skip qtype and qclass
        
        # Skip answer section
        header = DNSHeader.from_bytes(response[:12])
        for _ in range(header.ancount):
            offset = self.skip_rr(response, offset)
        
        # Parse NS records in authority section
        for _ in range(header.nscount):
            name, offset = self.parse_name(response, offset)
            rrtype, rrclass, ttl, rdlength = struct.unpack('!HHIH', response[offset:offset+10])
            offset += 10
            
            if rrtype == TYPE_NS:
                ns, _ = self.parse_name(response, offset)
                nameservers.append(ns)
            
            offset += rdlength
        
        return nameservers

    def parse_name(self, data, offset):
        name_parts = []
        while True:
            length = data[offset]
            if length == 0:
                offset += 1
                break
            elif length & 0xC0 == 0xC0:
                pointer = struct.unpack('!H', data[offset:offset+2])[0] & 0x3FFF
                name_parts.append(self.parse_name(data, pointer)[0])
                offset += 2
                break
            else:
                name_parts.append(data[offset+1:offset+1+length].decode())
                offset += length + 1
        return '.'.join(name_parts), offset

    def skip_rr(self, data, offset):
        _, offset = self.parse_name(data, offset)
        _, _, _, rdlength = struct.unpack('!HHIH', data[offset:offset+10])
        return offset + 10 + rdlength

    def check_cache(self, question):
        key = (question.qname, question.qtype, question.qclass)
        if key in self.cache:
            entry = self.cache[key]
            if entry.expire_time > time.time():
                return entry.data
            else:
                del self.cache[key]
        return None

    def update_cache(self, question, answer):
        key = (question.qname, question.qtype, question.qclass)
        expire_time = time.time() + 300  # Cache for 5 minutes
        self.cache[key] = CacheEntry(answer, expire_time)
    
    def build_response(self, header, question, full_response):
        answers, authorities, additionals = full_response
        
        header.qr = 1  # This is a response
        header.ra = 1  # Recursion available
        header.ancount = len(answers)
        header.nscount = len(authorities)
        header.arcount = len(additionals)
        
        response = header.to_bytes() + question.to_bytes()
        
        for answer in answers:
            response += self.encode_rr(answer)
        
        for authority in authorities:
            response += self.encode_rr(authority)
        
        for additional in additionals:
            response += self.encode_rr(additional)
        
        logging.debug(f"Response length: {len(response)}")
        logging.debug(f"Response hex: {response.hex()}")
        
        return response

    def parse_answer_section(self, answer):
        records = []
        offset = 0
        while offset < len(answer):
            name, offset = self.parse_name(answer, offset)
            if offset + 10 > len(answer):
                break
            type_, class_, ttl, rdlength = struct.unpack('!HHIH', answer[offset:offset+10])
            offset += 10
            rdata = answer[offset:offset+rdlength]
            offset += rdlength
            records.append((name, type_, class_, ttl, rdlength, rdata))
        return records

    def encode_rr(self, record):
        name, rrtype, rrclass, ttl, rdlength, rdata = record
        return self.encode_name(name) + struct.pack('!HHIH', rrtype, rrclass, ttl, rdlength) + rdata

    def encode_name(self, name):
        if isinstance(name, bytes):
            return name
        encoded = b''
        for label in name.split('.'):
            encoded += bytes([len(label)]) + label.encode()
        return encoded + b'\x00'

class DNSHeader:
    def __init__(self, id=None, qr=QR_QUERY, opcode=0, aa=0, tc=0, rd=1, ra=0, z=0, rcode=0, qdcount=1, ancount=0, nscount=0, arcount=0):
        self.id = id if id is not None else random.randint(0, 65535)
        self.qr = qr
        self.opcode = opcode
        self.aa = aa
        self.tc = tc
        self.rd = rd
        self.ra = ra
        self.z = z
        self.rcode = rcode
        self.qdcount = qdcount
        self.ancount = ancount
        self.nscount = nscount
        self.arcount = arcount

    @classmethod
    def from_bytes(cls, data):
        fields = struct.unpack('!HHHHHH', data)
        header = cls()
        header.id = fields[0]
        header.qr = (fields[1] & 0x8000) >> 15
        header.opcode = (fields[1] & 0x7800) >> 11
        header.aa = (fields[1] & 0x0400) >> 10
        header.tc = (fields[1] & 0x0200) >> 9
        header.rd = (fields[1] & 0x0100) >> 8
        header.ra = (fields[1] & 0x0080) >> 7
        header.z = (fields[1] & 0x0070) >> 4
        header.rcode = fields[1] & 0x000F
        header.qdcount = fields[2]
        header.ancount = fields[3]
        header.nscount = fields[4]
        header.arcount = fields[5]
        return header

    def to_bytes(self):
        fields = (self.id, 
                  (self.qr << 15) | (self.opcode << 11) | (self.aa << 10) | 
                  (self.tc << 9) | (self.rd << 8) | (self.ra << 7) | 
                  (self.z << 4) | self.rcode,
                  self.qdcount, self.ancount, self.nscount, self.arcount)
        return struct.pack('!HHHHHH', *fields)

class DNSQuestion:
    def __init__(self, qname, qtype, qclass):
        self.qname = qname
        self.qtype = qtype
        self.qclass = qclass

    @classmethod
    def from_bytes(cls, data):
        qname, offset = '', 0
        while True:
            length = data[offset]
            if length == 0:
                offset += 1
                break
            qname += data[offset+1:offset+1+length].decode() + '.'
            offset += length + 1
        qname = qname[:-1]  # Remove trailing dot
        qtype, qclass = struct.unpack('!HH', data[offset:offset+4])
        return cls(qname, qtype, qclass)

    def to_bytes(self):
        bqname = b''
        for label in self.qname.split('.'):
            bqname += bytes([len(label)]) + label.encode()
        bqname += b'\x00'
        return bqname + struct.pack('!HH', self.qtype, self.qclass)

if __name__ == "__main__":
    server = DNSServer()
    server.run()