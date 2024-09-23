from collections import namedtuple
import time

# Cache entry
CacheEntry = namedtuple('CacheEntry', ['data', 'expire_time'])

def check_cache(cache, question):
    key = (question.qname, question.qtype, question.qclass)
    if key in cache:
        entry = cache[key]
        if entry.expire_time > time.time():
            return entry.data
        else:
            del cache[key]
    return None
    
def update_cache(cache, question, answer):
    key = (question.qname, question.qtype, question.qclass)
    expire_time = time.time() + 300  # Cache for 5 minutes
    cache[key] = CacheEntry(answer, expire_time)
