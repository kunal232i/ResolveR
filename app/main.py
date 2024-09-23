import socket
import logging
from dns_header import DNSHeader
from dns_question import DNSQuestion
from dns_resolver import DNSResolver
import logging_config

logger = logging.getLogger(__name__)

class DNSServer:
    def __init__(self, host='127.0.0.1', port=2053):
        self.host = host
        self.port = port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind((self.host, self.port))
        self.resolver = DNSResolver()

    def run(self):
        logger.info(f"DNS Server running on {self.host}:{self.port}")
        while True:
            data, addr = self.socket.recvfrom(512)
            response = self.handle_query(data)
            self.socket.sendto(response, addr)

    def handle_query(self, data):
        header = DNSHeader.from_bytes(data[:12])
        question = DNSQuestion.from_bytes(data[12:])
        
        logger.info(f"Received query for {question.qname}")

        response = self.resolver.resolve(header, question)
        return response

if __name__ == "__main__":
    server = DNSServer()
    server.run()