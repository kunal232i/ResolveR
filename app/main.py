import logging
from dns_header import DNSHeader
from dns_question import DNSQuestion
from dns_resolver import DNSResolver
import logging_config
import asyncio
import time

logger = logging.getLogger(__name__)

BLACKLIST = ["malicious.com", "phishing.com"]

RATE_LIMIT = 5
client_query_rate = {}

MAX_QUERY_SIZE = 512  # Maximum allowed size for DNS queries

class DNSProtocol(asyncio.DatagramProtocol):
    def __init__(self, resolver):
        self.resolver = resolver

    def connection_made(self, transport):
        self.transport = transport
        logger.info('DNS Server is now listening for incoming requests')

    def datagram_received(self, data, addr):
        current_time = time.time()
        if addr in client_query_rate:
            if current_time - client_query_rate[addr][1] > 1:  # Reset counter every second
                client_query_rate[addr] = [1, current_time]
            else:
                client_query_rate[addr][0] += 1

            if client_query_rate[addr][0] > RATE_LIMIT:
                logger.warning(f"Rate limit exceeded for {addr}")
                return
        else:
            client_query_rate[addr] = [1, current_time]

        if len(data) > MAX_QUERY_SIZE:
            logger.warning(f"Query size exceeded for {addr}")
            return

        header = DNSHeader.from_bytes(data[:12])

        # DNS Amplification Attack Prevention: Check if RD flag is set
        if header.rd == 0:
            logger.warning(f"Recursion not requested from {addr}. Ignoring request.")
            return

        question = DNSQuestion.from_bytes(data[12:])

        if question.qname in BLACKLIST:
            logger.warning(f"Blocked request for blacklisted domain {question.qname} from {addr}")
            return

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