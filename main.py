from time import sleep
import config
from lib.server import Server

waiter = Server(
        name = "Waiter",
        type = "waiter",
        ip = config.WAITER[0], 
        port = config.WAITER[1], 
        transport = config.TRANSPORT, 
        buffer_size = config.BUFFER_SIZE, 
    )

kitchen = Server(
        name = "Kitchen",
        type = "kitchen",
        ip = config.KITCHEN[0], 
        port = config.KITCHEN[1], 
        transport = config.TRANSPORT, 
        buffer_size = config.BUFFER_SIZE, 
    )

print("")


target = config.KITCHEN
waiter.conn(target)

sleep(1)

waiter.send(message="hi!")