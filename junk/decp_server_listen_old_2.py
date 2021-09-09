import flask
import requests
import json
from multiprocessing.connection import Listener
from flask import Flask
from Crypto.PublicKey import ECC
from peewee import * # unclean, fix this shit

# url routes:
# - /<grouphash> for all group related things
# - / for everything else

app = Flask(__name__)

# initialize configs and db
config = None
with open("config.json", "r") as f:
    config = json.load(f)

db = SqliteDatabase(config["path_to_db"])
class BaseModel(Model):
    class Meta:
        database = db

class Known(BaseModel):
    addr = VARCHAR(unique=True)
    pubkey = VARCHAR(unique=True)
    nick = VARCHAR(unique=True)
    session = VARCHAR(unique=True)

db.connect()
db.create_tables([Known])

dc_operations = {"init": handle_init}

# direct communication
@app.route("/"), methods = ["GET", "POST"]
def handle_dc():
    dc_operations[request.form["op"]](request)

# group communication
@app.route("/<grouphash>"), methods = ["GET", "POST"]
def handle_gc(grouphash):
    pass

def handle_init(request):
    sender_pubkey, sender_addr, session_enc = request.form["pubkey"], request.form["addr"], request.form["session"]
    # implement callback to forntend to set nick
    # TODO - fix decrypt session
    session = session_enc
    sender_known = Known(pubkey=sender_pubkey, addr=sender_addr, nick=None, session=session)
    sender_known.save()

if __name__ == "__main__":
    app.run(debug=True, host="localhost")
