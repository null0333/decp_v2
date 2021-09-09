#   (                          )
#   )\ )  (          (   (  ( /(
#  (()/( ))\ (  `  ) )\  )\ )(_))
#   ((_))((_))\ /(/(((_)((_|(_)
#   _| (_)) ((_|(_)_\ \ / /|_  )
# / _` / -_) _|| '_ \) V /  / /
# \__,_\___\__|| .__/ \_/  /___|
#              |_|
#
# ---- this kills the discordcel - written by null333 ----
#

from ipcqueue import posixmq
import json
import requests
import base64
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256


class decp_send_server:
    def __init__():
        # put this in a different module and just import it
        self.config = None
        with open("config.json", "r") as f:
            self.config = json.load(f)

        self.privkey = None
        with open(config["priv.pem"]) as f:
            self.privkey = RSA.import_key(f.read())
        self.cipher_rsa_priv = PKCS1_OAEP.new(privkey)

        self.pubkey = None
        with open(config["pub.pem"]) as f:
            self.pubkey = RSA.import_key(f.read())
        self.cipher_rsa_pub = PKCS1_OAEP.new(pubkey)

        # ugly, idk how to clean this up
        self.db = SqliteDatabase(config["path_to_db"])
        class BaseModel(Model):
            class Meta:
                database = self.db

        class Known(BaseModel):
            addr = VARCHAR(unique=True)
            pubkey = VARCHAR(unique=True)
            nick = VARCHAR(unique=True)
            session_key = VARCHAR(unique=True)

        self.db.connect()
        self.db.create_tables([Known])

        self.queue = posixmq.Queue("/decp_send_queue")
        self.session = requests.session()
        self.session.proxies = {"http" : "socks5://127.0.0.1:9050",
                                "https" : "socks5://127.0.0.1:9050"}


    def start():
        while True:
            # [operation, args]
            op = self.queue.get(block=True)
            if op[0] == "send_init":
                send_init(op[1:])


    def send_init(self, args):
        # return 0 if no errors occured, -1 if errors occurred
        # args: recp_addr, path_to_recp_pubkey

        # TODO: sign session key
        session_key = get_random_bytes(32)
        signature = pkcs1_15.new(self.privkey).sign(SHA256.new(session_key))

        # replace this with key as string
        recp_key_rsa = None
        with open(args[1], "r") as f:
            recp_key_rsa = RSA.import_key(f.read())

        cipher_rsa = PKCS1_OAEP.new(recp_key_rsa)
        enc_session_key = base64.b64encode(cipher_rsa.encrypt(session_key))

        r = self.session.post(args[0], data={"pubkey" : self.pubkey.exportKey("PEM"),
                                         "addr" : config["addr"],
                                         "session_key" : enc_session_key,
                                         "signature" : signature
                                         })

         if r.json["accepted"] == "true":
             recp_enc_session_key = r.json["session_key"]
             session_key_recp = self.cipher_rsa_priv .decrypt(enc_session_key)

             if session_key_recp == session_key:
                try:
                    pkcs1_15.new(recp_key_rsa).verify(SHA256.new(session_key_recp), r.json["signature"])
                except (ValueError, TypeError):
                    return -1
                return 0

         return -1

     def send_message(self, args):
         # return 0 if no errors occured, 1otherwise
         # args: recp_addr
         recp = Known.get(addr == args[0])
         # cache ciphers to save memory?
         cipher_aes = AES.new(recp.session_key, AES.MODE_EAX)
         ciphertext, tag = cipher_aes.encrypt_and_digest(data)

         r = self.session.post(args[0], data={"addr" : config["addr",
                                              "message" : [cipher_aes.nonce, tag, ciphertext]]})
         try:
             r.json["ack"]
         except (KeyError):
             return -1
         return 0
