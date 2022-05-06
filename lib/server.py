import socket
import threading
import json

import os

from bitstring import BitArray
import binascii

import pyDH

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

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

            target = self.__find_target(address)
            key = None
            if len(target) == 3:
                key = target[2]

            # log & map payload
            self.__log(f"recieved payload: {payload} from: {address[0]}:{address[1]}")
            payload_dict, payload_is_corrupted = self.__map_payload_to_dict(payload, key=key)
            self.__log(f"decoded dict from payload: {payload_dict}")

            # check for corruption
            if payload_is_corrupted == True:
                self.__log("detected a corrupted package...")

            # check if first stage of handshake
            if payload_dict["syn"] == 1:

                # create shared key
                body = payload_dict["body"]
                pub_key = body["pub_key"]
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

                response_payload, size = self.__map_dict_to_payload(response_dict)

                # add target
                self.__add_target(address, shared_key)


                # send diffie hellman data
                self.__sendto(payload=response_payload, target=address, size=size)
            # check if second stage of handshake
            if payload_dict["ack"] == 1:

                # create shared key
                body = payload_dict["body"]
                pub_key = body["pub_key"]
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
            self.__log("SEND(); error: target list looks empty, did you establish a connection?")

        target = None
        if self.type == "waiter":
            target = self.targets[0]

        body = { "message": message }

        request_dict = {
            "syn": 0,
            "ack": 0,
            "fin": 0,
            "cor": 0,
            "body": body
        }

        key = None
        if target and len(target) > 2:
            key = target[2]

        request_payload, size = self.__map_dict_to_payload(request_dict, key=key)

        self.__log(f"sending {size} bits, payload: {request_payload}")

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

    def __map_dict_to_payload(self, data: dict, **kwargs):
        key = kwargs.get("key")

        # process body
        body_stringified = json.dumps(data.get("body") or {})

        if key is not None:
            self.__log(f"Key Detected: {key}. Encrypting body...")
            self.__log(f"Body before: {body_stringified} ")
            body_stringified = self.__encrypt_diffie_hellman(body_stringified, key)
            self.__log(f"Body after: {body_stringified} ")

        body_bitstring = self.__string_to_bitstring(body_stringified)


        # calculate sequence number
        sequence_number = 0
        if self.type == "kitchen": 
            sequence_number = data.get("sequence_number") or 0
            sequence_number = sequence_number + (32 + (len(body_bitstring))) // 8
        elif self.type == "waiter":
            sequence_number = (self.sequence_number + 32 + (len(body_bitstring))) // 8
            self.sequence_number = sequence_number

        sequence_number_bitstring = "{0:012b}".format(sequence_number) # use 12 bits to encode sequence_number

        # pack bits
        bitstring = ""
        bitstring += str(data.get("syn")) or str(0)
        bitstring += str(data.get("ack")) or str(0)
        bitstring += str(data.get("fin")) or str(0)
        bitstring += str(data.get("cor")) or str(0)
        bitstring += sequence_number_bitstring
        bitstring += body_bitstring
        checksum_bitstring = self.__calculate_checksum(bitstring) # calculate checksum bitstring based on accumulated bitstring so far

        if(len(checksum_bitstring) < 16):
            print("checksum length is short wtf")

        bitstring = checksum_bitstring + bitstring

        # return bytes and size of bitstring
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
    def __map_payload_to_dict(self, payload: bytes, **kwargs):
        key = kwargs.get("key")

        # convert bytes to bitstring
        bitstring = self.__bytes_to_bitstring(payload)

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
        body_string = self.__bitstring_to_bytes(body).decode("utf-8")

        if key is not None:
            self.__log(f"Found key: {key}")
            body_string = self.__decrypt_diffie_hellman(body_string, key)

        # decode decimal int from bits
        sequence_number_int = int(sequence_number, 2)

        payload_dict = {
            "syn": int(syn),
            "ack": int(ack),
            "fin": int(fin),
            "cor": int(cor),
            "sequence_number": sequence_number_int,
            "checksum": checksum,
            "body": json.loads(body_string),
        }

        return payload_dict, corrupted

    def __calculate_checksum(self, bitstring: str) -> str:
        return "{0:016b}".format(binascii.crc_hqx(self.__bitstring_to_bytes(bitstring), 0))

    def __encrypt_diffie_hellman(self, body: str, key: str):
        iv = os.urandom(16)
        cipher = AES.new(key[:16], AES.MODE_CBC, iv)

        ciphertext = cipher.encrypt(pad(body))
        print(f"ciphertext: {ciphertext}")

        return ciphertext

    def __decrypt_diffie_hellman(self, body: str, key: str):
        iv = os.urandom(16)
        print(key)
        cipher = AES.new(key[:16], AES.MODE_CBC, iv)

        deciphered = cipher.decrypt(body)
        print(f"deciphered: {deciphered}")

        return deciphered
        


    def __string_to_bitstring(self, s: str):
        ords = (ord(c) for c in s)
        shifts = (7, 6, 5, 4, 3, 2, 1, 0)
        bitlist = [str((o >> shift) & 1) for o in ords for shift in shifts]
        bitstring = ''.join(bitlist)
        return bitstring

    def __bitstring_to_bytes(self, s: str):
        return int(s, 2).to_bytes((len(s) + 7) // 8, byteorder='big')

    def __bytes_to_bitstring(self, bytes: bytes):
        return BitArray(bytes=bytes).bin

    # adds target to the list of targets if it is not there already
    def __add_target(self, target, shared_key):
        if target not in self.targets:
            self.targets.append((target[0], target[1], shared_key))
            self.__log(
                f"connection added to targets. Targets list: {self.targets}")

    def __find_target(self, address: tuple):
        target = [(ip, port, diffie) for ip, port, diffie in self.targets if ip == address[0] and port == address[1]]
        return target

    # logs a message to the console using self values as identifiers
    def __log(self, message):
        # add additional space to input so that [WAITER] and [KITCHEN] have the same length lol
        space = " " if self.type == "waiter" else ""

        print(f"[{self.name.upper()}]{space} {message}")

    # raw __sendto wrapper
    def __sendto(self, *, payload: bytes, target: tuple, **kwargs):

        if kwargs.get("size"):
            self.__log(f"sending {kwargs.get('size')} bits")

        self.UDPServerSocket.sendto(payload, target[:2])
