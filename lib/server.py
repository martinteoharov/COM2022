import socket
import threading
from bitstring import BitArray

class Server:
    def __init__(self, *, name: str, type: str, ip: str, port: int, transport: str, bufferSize: int):
        # set values
        self.name = name
        self.type = type
        self.ip = ip
        self.port = port
        self.bufferSize = bufferSize
        self.transport = transport
        self.targets = []
        self.sequenceNumber = 0
        

        # define socket type (UDP)
        self.socket_type = socket.SOCK_DGRAM if transport == "UDP" else socket.SOCK_STREAM

        # create UDPServerSocket
        self.UDPServerSocket = socket.socket(family=socket.AF_INET, type=self.socket_type)

        # Bind to address and ip
        self.UDPServerSocket.bind((self.ip, self.port))

        # Start listening thread
        self.thread = threading.Thread(target=self.listen)
        self.thread.start()
    

    # This function boots up a thread that listens for incoming messages on the defined UDP socket
    def listen(self):
        # Log startup
        self.__log(f"PASSIVE OPEN {self.ip}:{self.port} ({self.transport})")

        while True:
            # bytes contains the request, address contains the requesting person's address
            payload, address = self.UDPServerSocket.recvfrom(self.bufferSize)

            self.__log(f"recieved payload: {payload} from: {address[0]}:{address[1]}")

            payload_dict = self.__map_payload_to_dict(payload)
            self.__log(f"decoded payload to dict: {payload_dict}")

            if bytes == "SYN":
                pass

            

            # self.__add_target(target)

    # 
    # Establish a connection with your specified target.
    # 
    # This function performs a TCP-like three-way handshake with the target. (https://www.vskills.in/certification/tutorial/tcp-connection-establish-and-terminate/)
    # args: target
    # returns: targets list
    # 
    def conn(self, target):
        payload = self.__encode("SYN")
        print(payload)

        self.__sendto(payload, target)

    # Builds and sends a packet
    def send(self, message):
        if not self.targets:
            self.__log("SEND(); error: target list looks empty, did you establish a connection?")
            

        for target in self.targets:
            self.__log(f"sending \"{message}\" to {target[0]}:{target[1]}")
            self.__sendto(self.__encode(message), target)


    # adds target to the list of targets if it is not there already
    def __add_target(self, target):
        if target not in self.targets:
            self.targets.append(target)
            self.__log(f"connection added to targets. Targets list: {self.targets}")

    # logs a message to the console using self values as identifiers
    def __log(self, message):
        # add additional space to input so that [WAITER] and [KITCHEN] have the same length lol
        space = " " if self.type == "waiter" else ""

        print(f"[{self.name.upper()}]{space} {message}")

    # raw __sendto wrapper
    def __sendto(self, *args):
        self.UDPServerSocket.sendto(*args)

    # encodes message in utf 8
    def __encode(self, message: str):
        return str.encode(message)

    # Example dict format argument:
    #
    # {
    #   syn: int (0 or 1),
    #   ack: int (0 or 1),
    #   fin: int (0 or 1),
    #   body: string (json dumps),
    # }
    # 
    # checksum & sequence number are being calculated here
    #
    def __map_dict_to_payload(self, data: dict):
        print(data)

        #  
        bitstring = f"0b{data.get('syn')}{data.get('ack')}{data.get('fin')}"
        
        if sequence_number < 4096:
            # calculate new sequence number
            sequence_number = self.sequenceNumber + 47 + len(data.get("body"))
            self.sequenceNumber = sequence_number

            seq_bitstring = "{0:012b}".format(sequence_number)
        else:
            print("SEQUENCE NUMBER TOO HIGH BLYAT")

        bitstring += seq_bitstring


        print(bitstring)


    def __map_payload_to_dict(self, payload: bytes):
        S = payload[0]
        A = payload[1]
        sequence_number = payload[6:16]
        checksum = payload[16:47]
        body = payload[48:]

        return { S, A, sequence_number, checksum, body }




















# def create(*, ip: str, port: int, transport: str, bufferSize: int, name: str):
#     socket_type = socket.SOCK_DGRAM if transport == "UDP" else socket.SOCK_STREAM
#     UDPServerSocket = socket.socket(family=socket.AF_INET, type=socket_type)

#     # Bind to address and ip
#     # 127.0.0.1 
#     UDPServerSocket.bind((ip, port))

#     # Log startup
#     print(f"Server '{name}' up and listening on {ip}:{port} ({transport})")

#     # Start listening thread
#     t = threading.Thread(target=listen, args=(bufferSize, UDPServerSocket, name))
#     t.start()

#     return UDPServerSocket
