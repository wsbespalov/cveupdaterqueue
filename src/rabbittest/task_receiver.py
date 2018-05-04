import redis


from settings import SETTINGS
from config import Config


config = Config(SETTINGS)

cache = redis.StrictRedis(
    host=config.cache.host,
    port=config.cache.port,
    db=config.cache.db
)

print(cache)