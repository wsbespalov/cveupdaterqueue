import pika
import redis

import settings
import config

config = config.Config(settings.SETTINGS)

cache = redis.StrictRedis(
    host=config.cache.host,
    port=config.cache.port,
    db=config.cache.db
)


class TaskListener(object):

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
        self.channel.basic_consume(
            self.callback,
            queue=config.queues.create,
            no_ack=config.pika.no_ack
        )
        self.channel.start_consuming()

t = TaskListener()
t.basic_consume()
    

    