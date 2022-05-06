import socket
import threading
import json

from bitstring import BitArray
import binascii

import pyDH


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

        # define diffie hellman stuff
        self.dh = pyDH.DiffieHellman()
        self.pub_key = self.dh.gen_public_key()

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

    # this function boots up a thread that listens for incoming messages on the defined UDP socket
    def listen(self):
        # Log startup
        self.__log(f"PASSIVE OPEN {self.ip}:{self.port} ({self.transport})")

        while True:
            # payload contains the request in bytes, address contains the requesting person's address
            payload, address = self.UDPServerSocket.recvfrom(self.buffer_size)
            print("")

            # log & map payload
            #self.__log(f"recieved payload: {payload} from: {address[0]}:{address[1]}")
            payload_dict, payload_is_corrupted = self.__map_payload_to_dict(
                payload)
            self.__log(f"decoded dict from payload: {payload_dict}")

            # check for corruption
            if payload_is_corrupted == True:
                self.__log("detected a corrupted package...")

            # check if first stage of handshake
            if payload_dict["syn"] == 1:

                # create shared key
                body = payload_dict.get("body")
                pub_key = body.get("pub_key")
                shared_key = self.dh.gen_shared_key(pub_key)

                diffie_hellman = {"pub_key": self.pub_key}

                response_dict = {
                    "syn": 0,
                    "ack": 1,
                    "fin": 0,
                    "cor": 0,
                    "sequence_number": payload_dict.get("sequence_number"),
                    "body": diffie_hellman
                }

                response_payload, size = self.__map_dict_to_payload(
                    response_dict)

                # add target
                self.__add_target(address, shared_key)

                # send diffie hellman data
                self.__sendto(payload=response_payload, target=address, size=size)
            # check if second stage of handshake
            if payload_dict["ack"] == 1:

                # create shared key
                body = payload_dict.get("body")
                pub_key = body.get("pub_key")
                shared_key = self.dh.gen_shared_key(pub_key)

                # add target
                self.__add_target(address, shared_key)

    # This function initiates a TCP-like two-way handshake with the target. (https://www.vskills.in/certification/tutorial/tcp-connection-establish-and-terminate/)
    #
    # args: target
    # returns: void

    def conn(self, target: tuple) -> None:
        # define diffie_hellman stuff
        diffie_hellman = {"pub_key": self.pub_key}

        payload_dict = {
            "syn": 1,
            "ack": 0,
            "fin": 0,
            "cor": 0,
            "body": diffie_hellman
        }

        payload, size = self.__map_dict_to_payload(payload_dict)

        self.__sendto(payload=payload, target=target, size=size)

    # Builds and sends a packet
    def send(self, *, message):
        if not self.targets:
            self.__log(
                "SEND(); error: target list looks empty, did you establish a connection?")

        target = None
        if self.type == "waiter":
            target = self.targets[0]

        request_dict = {
            "syn": 0,
            "ack": 0,
            "fin": 0,
            "cor": 0,
            "body": {message: message}
        }

        request_payload, = self.__map_dict_to_payload(request_dict)

        print(target)

        self.__sendto(payload=request_payload, target=target)

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
        # process body
        body_json_stringified = json.dumps(data.get("body") or {})
        body_json_stringified_bitstring = self.__string_to_bitstring(
            body_json_stringified)

        # calculate sequence number
        sequence_number = 0
        if self.type == "kitchen":
            sequence_number = data.get(
                "sequence_number") + (32 + (len(body_json_stringified_bitstring))) // 8

        elif self.type == "waiter":
            # calculate new sequnce_number
            sequence_number = (self.sequence_number + 32 +
                               (len(body_json_stringified_bitstring))) // 8

            self.sequence_number = sequence_number

        if sequence_number > 10000:
            self.__log("SEQUENCE NUMBER TOO HIGH BLYAT")

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
        checksum_bitstring = self.__calculate_checksum(bitstring)

        if(len(checksum_bitstring) < 16):
            print("checksum length is short wtf")

        bitstring = checksum_bitstring + bitstring

        return self.__bitstring_to_bytes(bitstring), len(bitstring)

    #
    # Returns
    # {
    #   syn: int,
    #   ack: int,
    #   fin: int,
    #   cor: int,
    #   body: dict,
    #   sequence_number: int,
    #   checksum: bitstring,
    #   corruputed: boolean
    # }
    #
    #
    def __map_payload_to_dict(self, payload: bytes):
        # convert bytes to bitarray
        bitstring = BitArray(bytes=payload).bin

        self.__log(f"recieved {len(bitstring)} bits")

        checksum = bitstring[0:16]
        syn = bitstring[16]
        ack = bitstring[17]
        fin = bitstring[18]
        cor = bitstring[19]
        sequence_number = bitstring[20:32]
        body = bitstring[32:]

        expected_checksum = self.__calculate_checksum(bitstring[16:])

        corrupted = False
        if checksum == expected_checksum:
            self.__log("checksum matches...")
        else:
            self.__log("[!] CHECKSUM MISSMATCH")
            corrupted = True

        # convert body bitstring to bytes obj
        body_bytes = self.__bitstring_to_bytes(body)

        # decode decimal int from bits
        sequence_number_int = int(sequence_number, 2)

        payload_dict = {
            "syn": int(syn),
            "ack": int(ack),
            "fin": int(fin),
            "cor": int(cor),
            "sequence_number": sequence_number_int,
            "checksum": checksum,
            "body": json.loads(body_bytes),
        }

        return payload_dict, corrupted

    def __calculate_checksum(self, bitstring: str) -> str:
        return "{0:016b}".format(binascii.crc_hqx(self.__bitstring_to_bytes(bitstring), 0))

    def __decrypt_diffie_hellman(self, bytes, target):
        pass

    def __encrypt_diffie_hellman(self, bytes, target):
        pass

    def __string_to_bitstring(self, s: str):
        ords = (ord(c) for c in s)
        shifts = (7, 6, 5, 4, 3, 2, 1, 0)
        bitlist = [str((o >> shift) & 1) for o in ords for shift in shifts]
        bitstring = ''.join(bitlist)
        return bitstring

    def __bitstring_to_bytes(self, s: str):
        return int(s, 2).to_bytes((len(s) + 7) // 8, byteorder='big')

    # adds target to the list of targets if it is not there already
    def __add_target(self, target, shared_key):
        if target not in self.targets:
            self.targets.append((target[0], target[1], shared_key))
            self.__log(
                f"connection added to targets. Targets list: {self.targets}")

    # logs a message to the console using self values as identifiers
    def __log(self, message):
        # add additional space to input so that [WAITER] and [KITCHEN] have the same length lol
        space = " " if self.type == "waiter" else ""

        print(f"[{self.name.upper()}]{space} {message}")

    # raw __sendto wrapper
    def __sendto(self, *, payload, target, **kwargs):

        print(payload, target)

        if kwargs.get("size"):
            self.__log(f"sending {kwargs.get('size')} bits")

        encrypted_bitstring = self.__encrypt_diffie_hellman(payload, target)

        self.UDPServerSocket.sendto(payload, target)

    # encodes message in utf 8
    def __encode(self, message: str):
        return str.encode(message)
