SETTINGS = dict(
    cache = dict(
        host='localhost',
        port=6379,
        db=1
    ),
    queue = dict(
        create="create_queue",
        delete="delete_queue",
        update="update_queue"
    )
)