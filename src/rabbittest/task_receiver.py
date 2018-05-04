import pika
import redis
from abc import ABC, abstractmethod

from .settings import SETTINGS
from .config import Config

config = Config(SETTINGS)

cache = redis.StrictRedis(
    host=config.cache.host,
    port=config.cache.port,
    db=config.cache.db
)
storage = redis.StrictRedis(
    host=config.storage.host,
    port=config.storage.port,
    db=config.storage.db
)


class CacheConnector(object):
    pass


class StorageConnector(object):
    pass

class TaskListenerBase(ABC):
    connection = None
    channel = None

    @abstractmethod
    def callback(self, ch, method, properties, body):
        pass

    @abstractmethod
    def basic_consume(self):
        pass
   

class CreateTaskListener(TaskListenerBase):
    
    def __init__(self, *args, **kwargs):
        self.connection = pika.BlockingConnection(
            pika.ConnectionParameters(
                config.pika.host
            )
        )
        self.channel = self.connection.channel()
        self.channel.queue_declare(
            queue=config.queues.create
        )

    def callback(self, ch, method, properties, body):
        print('[x] Receive {}'.format(body))

    def basic_consume(self):
        print('Start consuming...  Type Ctrl+C to exit...')
        self.channel.basic_consume(
            self.callback,
            queue=config.queues.create,
            no_ack=config.pika.no_ack
        )
        self.channel.start_consuming()



t = CreateTaskListener()
t.basic_consume()