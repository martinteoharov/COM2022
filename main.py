from curses.ascii import CAN
from time import sleep
import config as config
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