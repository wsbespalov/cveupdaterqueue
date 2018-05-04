

class Config(object):
    class Redis(object):
        def __init__(self, cache={}):
            self.host = cache.get("host", 'localhost')
            self.port = cache.get("port", 6379)
            self.db = cache.get("db", 1)
    def __init__(self, settings={}):
        self.settings = settings
        self.cache = Redis(settings.get("cache", {}))