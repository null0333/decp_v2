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

import requests
import json
import base64
from flask import Flask
from peewee import * # unclean, fix this shit
from ipcqueue import posixmq

# url routes:
# - /<grouphash> for all group related things
# - / for everything else

app = Flask(__name__)

# initialize configs and db
# very unclean, all of this shit is global
config = None
with open("config.json", "r") as f:
    config = json.load(f)

privkey = None
with open(config["priv.pem"]) as f:
    privkey = RSA.import_key(f.read())
cipher_rsa_priv = PKCS1_OAEP.new(privkey)

pubkey = None
with open(config["pub.pem"]) as f:
    pubkey = RSA.import_key(f.read())
cipher_rsa_pub = PKCS1_OAEP.new(pubkey)

db = SqliteDatabase(config["path_to_db"])
class BaseModel(Model):
    class Meta:
        database = db

class Known(BaseModel):
    addr = VARCHAR(unique=True)
    pubkey = VARCHAR(unique=True)
    nick = VARCHAR(unique=True)
    session_key = VARCHAR(unique=True)

db.connect()
db.create_tables([Known])

send_queue = posixmq.Queue("/decp_send_queue")
frontend_queue = posixmq.Queue("/decp_frontend_queue")

dc_operations = {"init": handle_init}

# direct communication
@app.route("/"), methods = ["GET", "POST"]
def handle_dc():
    dc_operations[request.json["op"]](request)

# group communication
@app.route("/<grouphash>"), methods = ["GET", "POST"]
def handle_gc(grouphash):
    pass

def handle_init(request):
    # TODO: handle user interaction
    sender_pubkey = request.json["pubkey"],
    sender_addr = request.json["addr"]
    session_enc = request.json["session_key"]
    signature = request.json["signature"]

    # implement callback to forntend to set nick
    # TODO - fix decrypt session

    session_key = cipher_rsa_priv.decrypt(base64.b64decode(session_enc))

    sender_known = Known(pubkey=sender_pubkey,
                         addr=sender_addr,
                         nick=None,
                         session=session_key)
    sender_known.save()

    self.send_queue.put()

def handle_message(request):
    sender_addr = request.json["addr"]
    enc_message = request.json["message"]
    sender = db.get(addr == sender_addr)
    session_key = sender.session_key
    cipher_aes = AES.new(session_key, AES.MODE_EAX, enc_message[0])

    # move message to redis queue
    message = cipher_aes.decrypt_and_verify(enc_message[2], enc_message[1])
    try:
        pkcs1_15.new(sender.pubkey).verify(SHA256.new(session_key), r.json["signature"])
    except (ValueError, TypeError):
        return -1


    return 0


if __name__ == "__main__":
    app.run(debug=True, host="localhost")
