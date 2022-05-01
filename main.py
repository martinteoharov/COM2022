import config
from lib.server import Server

waiter = Server(
        name = "Waiter",
        type = "waiter",
        ip = config.waiter[0], 
        port = config.waiter[1], 
        transport = config.transport, 
        buffer_size = config.buffer_size, 
    )

kitchen = Server(
        name = "Kitchen",
        type = "kitchen",
        ip = config.kitchen[0], 
        port = config.kitchen[1], 
        transport = config.transport, 
        buffer_size = config.buffer_size, 
    )

print("")


target = config.kitchen
waiter.conn(target)



# raw sendto
# waiter.sendto(encode("Hello cunt!"), (config.kitchen["ip"], config.kitchen["port"]))

# raw sendto
# kitchen.sendto(encode("Hello cunt!"), (config.waiter["ip"], config.waiter["port"]))
