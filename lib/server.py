import socket
import threading
import json

from bitstring import BitArray
import binascii

class Server:
    def __init__(self, *, name: str, type: str, ip: str, port: int, transport: str, buffer_size: int):
        # set values
        self.name = name
        self.type = type
        self.ip = ip
        self.port = port
        self.buffer_size = buffer_size
        self.transport = transport
        self.targets = []

        # define a sequence number
        if type == "waiter":
            self.sequence_number = 0

        # define socket type (UDP)
        self.socket_type = socket.SOCK_DGRAM if transport == "UDP" else socket.SOCK_STREAM

        # create UDPServerSocket
        self.UDPServerSocket = socket.socket(
            family=socket.AF_INET, type=self.socket_type)

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
            payload, address = self.UDPServerSocket.recvfrom(self.buffer_size)
            print("")

            self.__log(f"recieved payload: {payload} from: {address[0]}:{address[1]}")

            payload_dict = self.__map_payload_to_dict(payload)

            self.__log(f"decoded dict from payload: {payload_dict}")

            if payload_dict["syn"] == 1:
                diffie_hellman = {"kur": "kapan"}
                response_dict = {
                    "syn": 0,
                    "ack": 1,
                    "fin": 0,
                    "cor": 0,
                    "sequence_number": payload_dict.get("sequence_number") or 0,
                    "body": diffie_hellman
                }

                response_payload, size = self.__map_dict_to_payload(response_dict)

                self.__add_target(address)

                self.__sendto(response_payload, address, size = size)

            if payload_dict["ack"] == 1:
                self.__add_target(address)


    # This function initiates a TCP-like two-way handshake with the target. (https://www.vskills.in/certification/tutorial/tcp-connection-establish-and-terminate/)
    #
    # args: target
    # returns: void
    def conn(self, target: tuple) -> None:
        diffie_hellman = {"kur": "kapan"}

        payload_dict = {
            "syn": 1,
            "ack": 0,
            "fin": 0,
            "cor": 0,
            "body": diffie_hellman
        }

        payload, size = self.__map_dict_to_payload(payload_dict)

        self.__sendto(payload, target, size = size)

    # Builds and sends a packet
    def send(self, message):
        if not self.targets:
            self.__log(
                "SEND(); error: target list looks empty, did you establish a connection?")

        for target in self.targets:
            self.__log(f"sending \"{message}\" to {target[0]}:{target[1]}")
            self.__sendto(self.__encode(message), target)

    # adds target to the list of targets if it is not there already
    def __add_target(self, target):
        if target not in self.targets:
            self.targets.append(target)
            self.__log(
                f"connection added to targets. Targets list: {self.targets}")

    # logs a message to the console using self values as identifiers
    def __log(self, message):
        # add additional space to input so that [WAITER] and [KITCHEN] have the same length lol
        space = " " if self.type == "waiter" else ""

        print(f"[{self.name.upper()}]{space} {message}")

    # raw __sendto wrapper
    def __sendto(self, *args, **kwargs):
        if kwargs.get("size"):
            self.__log(f"sending {kwargs.get('size')} bits, payload: {args[0]}")

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
    def __map_dict_to_payload(self, data: dict):
        self.__log(f"mapping dict: {data} to payload")

        # process body
        body_json_stringified = json.dumps(data.get("body") or {})
        body_json_stringified_bitstring = self.__string_to_bitstring(body_json_stringified)

        sequence_number = 0
        if self.type == "kitchen":
            sequence_number = data.get("sequence_number") + 48 + (len(body_json_stringified_bitstring) // 8)

        elif self.type == "waiter":
            # calculate new sequnce_number
            sequence_number = self.sequence_number + 48 + (len(body_json_stringified_bitstring) // 8)

            if sequence_number > 4096:
                self.__log("SEQUENCE NUMBER TOO HIGH BLYAT")
            else:
                self.sequence_number = sequence_number
            
        # use 12 bits to encode sequence_number
        sequence_number_bitstring = "{0:012b}".format(sequence_number)

        # pack bits
        bitstring = ""
        bitstring += str(data.get("syn")) or str(0)
        bitstring += str(data.get("ack")) or str(0)
        bitstring += str(data.get("fin")) or str(0)
        bitstring += str(data.get("cor")) or str(0)
        bitstring += sequence_number_bitstring
        bitstring += body_json_stringified_bitstring

        # calculate checksum bitstring based on accumulated bitstring so far 
        checksum_bitstring = "{:0b}".format(binascii.crc_hqx(self.__bitstring_to_bytes(bitstring), 0))

        if len(checksum_bitstring) < 16:
            print("Checksum is shorter than 16 hmmm")
            checksum_bitstring = 16 * "0"

        # define 0b in the end so we dont need to take into account the first 2 indexes when manipulating the data
        bitstring = "0b" + checksum_bitstring + bitstring

        return self.__bitstring_to_bytes(bitstring), len(bitstring) - 2

    # 
    # Returns
    # {
    #   syn: int,
    #   ack: int,
    #   fin: int,
    #   body: dict,
    #   sequence_number: int,
    #   checksum: bitstring,
    # }
    #
    #
    def __map_payload_to_dict(self, payload: bytes):
        # convert bytes to bitarray and remove first 8 bits (TODO: investigate why the function returns 1 zero-ed byte in front)
        bitstring = BitArray(bytes=payload).bin[8:]
        
        checksum = bitstring[0:16]
        syn = bitstring[16]
        ack = bitstring[17]
        fin = bitstring[18]
        cor = bitstring[19]
        sequence_number = bitstring[20:31]
        body = bitstring[32:]

        checksum_bytes = self.__bitstring_to_bytes(checksum)
        sequence_number_bytes = self.__bitstring_to_bytes(sequence_number)
        body_bytes = self.__bitstring_to_bytes(body)

        sequence_number_int = 69

        payload_dict = {
            "syn": int(syn), 
            "ack": int(ack), 
            "fin": int(fin), 
            "cor": int(cor), 
            "sequence_number": sequence_number_int, 
            "checksum": checksum, 
            "body": json.loads(body_bytes)
        }

        return payload_dict

    def __string_to_bitstring(self, s: str):
        ords = (ord(c) for c in s)
        shifts = (7, 6, 5, 4, 3, 2, 1, 0)
        bitlist = [str((o >> shift) & 1) for o in ords for shift in shifts]
        bitstring = ''.join(bitlist)
        return bitstring

    def __bitstring_to_bytes(self, s: str):
        return int(s, 2).to_bytes((len(s) + 7) // 8, byteorder='big')
