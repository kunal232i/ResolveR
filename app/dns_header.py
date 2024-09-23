import struct
import random
from constants import QR_QUERY

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
