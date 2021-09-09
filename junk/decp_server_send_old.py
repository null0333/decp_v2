from ipcqueue import posixmq
import json
import requests
# https://github.com/ecies/py
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from ecies import encrypt, decrypt

class decp_send_server:
    def __init__():
        config = None
        with open("config.json", "r") as f:
            config = json.load(f)

        self.queue = posixmq.Queue("/decp_server_queue")
        self.session = requests.session()
        self.session.proxies = {"http" : "socks5://127.0.0.1:9050",
                                "https" : "socks5://127.0.0.1:9050"}

        while True:
            # [operation, args]
            op = queue.get(block=True)
            if op[0] == "send_init":
                send_init(op[1:])

    def send_init(self, args):
        # args: recp_addr,
        key = get_random_bytes(32)
        cipher = AES.new(key, AES.MODE_EAX)
        nonce = cipher.nonce


        self.session.post(args[0], )
