import flask
import requests
from multiprocessing.connection import Listener
from flask import Flask
from Crypto.PublicKey import ECC
from peewee import * # unclean, fix this shit

class decp_server:
    # url routes:
    # - /<grouphash> for all group related things
    # - / for everything else

    def __init__(self, config_dir):
        self.app = Flask(__name__)
        self.dc_operations = {"init": self.handle_init}

    class BaseModel(Model):
        class Meta:
            database = db

    # direct communication
    @self.app.route("/"), methods = ["GET", "POST"]
    def handle_dc():
        self.dc_operations[request.form["op"]](request)
    # group communication
    @self.app.route("/<grouphash>"), methods = ["GET", "POST"]
    def handle_gc(grouphash):
        if request.method == "GET":
            pass
        else if request.method == "POST":
            pass


    def handle_init(self, request):
        sender_pubkey, sender_addr, sender_nick = request.form["pubkey"], request.form["addr"], request.form["nick"]
