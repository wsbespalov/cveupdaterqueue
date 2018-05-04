import pika
import json

queue_name_create = "create_queue"
queue_name_update = "update"

connection = pika.BlockingConnection(pika.ConnectionParameters(host='localhost'))

channel = connection.channel()

channel.queue_declare(queue=queue_name_create)

body = {
    "message": "create vulner"
}
body = json.dumps(body)

channel.basic_publish(exchange='', routing_key=queue_name_create, body=body)
print('[x] Send Create message')
connection.close()