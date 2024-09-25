import logging
from logging.handlers import RotatingFileHandler

def configure_logging():
    logging.basicConfig(
        level=logging.DEBUG,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S',
        handlers=[
            RotatingFileHandler('dns_server.log', maxBytes=10485760, backupCount=5)
        ]
    )

configure_logging()
