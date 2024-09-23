import socket
import struct
from dns_header import DNSHeader
from cache import check_cache, update_cache
from constants import TYPE_NS
import logging
import logging_config

logger = logging.getLogger(__name__)

class DNSResolver:
    def __init__(self):
        self.cache = {}

    def resolve(self, header, question):
        cached_response = check_cache(self.cache, question)
        if cached_response:
            logger.info(f"Cache hit for {question.qname}")
            return self.build_response(header, question, cached_response)

        logger.info(f"Cache miss for {question.qname}, performing recursive query")
        full_response = self.recursive_query(question)
        
        if full_response:
            update_cache(self.cache, question, full_response)
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
                        return self.parse_full_response(response)
                    elif header.nscount > 0:
                        nameservers = self.extract_nameservers(response)
                        break
                    else:
                        return None
                except Exception as e:
                    logger.error(f"Error querying {ns}: {e}")
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
        
        return response

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

    def build_error_response(self, header, question):
        header.qr = 1  # This is a response
        header.rcode = 3  # NXDOMAIN
        return header.to_bytes() + question.to_bytes()