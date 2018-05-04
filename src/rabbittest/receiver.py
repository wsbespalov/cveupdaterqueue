import pika


queue_name_create = "create"
queue_name_update = "update"

connection = pika.BlockingConnection(pika.ConnectionParameters(host='localhost'))

channel = connection.channel()

channel.queue_declare(queue=queue_name_create)

def callback(ch, method, properties, body):
    print('[x] Receive {}'.format(body))

channel.basic_consume(callback, queue=queue_name_create, no_ack=False)

print('[x] Wainting to cumsume...')

channel.start_consuming()