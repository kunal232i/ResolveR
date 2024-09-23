import struct

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
