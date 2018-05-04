class Redis(object):
    def __init__(self, cache={}):
        self.host = cache.get("host", 'localhost')
        self.port = cache.get("port", 6379)
        self.db = cache.get("db", 1)

class Queues(object):
    def __init__(self, queues={}):
        self.create = queues.get("create", "create_queue")
        self.delete = queues.get("delete", "delete_queue")
        self.update = queues.get("update", "update_queue")

class Collections(object):
    def __init__(self, collections={}):
        self.separator = collections.get("separator", "::")
        self.index = collections.get("index", "index")
        self.vulners = collections.get("vulners", "vulners")

class Pika(object):
    def __init__(self, pika={}):
        self.host = pika.get("host", "localhost")
        self.no_ack = pika.get("no_ack", True)

class Config(object):
    def __init__(self, settings={}):
        self.settings = settings
        self.cache = Redis(settings.get("cache", {}))
        self.queues = Queues(settings.get("queues", {}))
        self.collections = Collections(settings.get("collections", {}))
        self.pika = Pika(settings.get("pika", {}))