import logging
from dns_header import DNSHeader
from dns_question import DNSQuestion
from dns_resolver import DNSResolver
import logging_config
import asyncio

logger = logging.getLogger(__name__)

class DNSProtocol(asyncio.DatagramProtocol):
    def __init__(self, resolver):
        self.resolver = resolver

    def connection_made(self, transport):
        self.transport = transport
        logger.info('DNS Server is now listening for incoming requests')

    def datagram_received(self, data, addr):
        logger.info(f'Received data from {addr}')
        header = DNSHeader.from_bytes(data[:12])
        question = DNSQuestion.from_bytes(data[12:])
        response = self.resolver.resolve(header, question)
        self.transport.sendto(response, addr)

class AsyncDNSServer:
    def __init__(self, host='127.0.0.1', port=2053):
        self.host = host
        self.port = port
        self.resolver = DNSResolver()

    async def run(self):
        loop = asyncio.get_event_loop()
        listen = loop.create_datagram_endpoint(
            lambda: DNSProtocol(self.resolver),
            local_addr=(self.host, self.port)
        )
        transport, protocol = await listen
        logger.info(f"DNS Server running on {self.host}:{self.port}")
        await asyncio.sleep(3600)  # Keep server running

if __name__ == "__main__":
    server = AsyncDNSServer()
    asyncio.run(server.run())