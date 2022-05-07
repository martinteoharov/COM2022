from curses.ascii import CAN
from time import sleep
import config
from lib.server.server import Server
from lib.server.commands import CANCEL_ORDER, CREATE_ORDER

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
print("")

# Create order
create_order_dict = CREATE_ORDER(waiter_id=1, table_id=1, order=["fish"])
waiter.send(payload_dict=create_order_dict)

sleep(1)
print("")

# Cancel order
cancel_order_dict = CANCEL_ORDER(waiter_id=1, table_id=1)
waiter.send(payload_dict=cancel_order_dict)