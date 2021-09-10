config = None
with open("config.json", "r") as f:
    config = json.load(f)

privkey = None
with open(config["priv.pem"]) as f:
    privkey = RSA.import_key(f.read())

pubkey = None
with open(config["pub.pem"]) as f:
    pubkey = RSA.import_key(f.read())

# ugly, idk how to clean this up
db = SqliteDatabase(config["path_to_db"])
class BaseModel(Model):
    class Meta:
        database = self.db

class Known(BaseModel):
    addr = VARCHAR(unique=True)
    pubkey = VARCHAR(unique=True)
    nick = VARCHAR(unique=True)
    session_key = VARCHAR(unique=True)

db.connect()
db.create_tables([Known])
