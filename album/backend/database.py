import bson
import json
import pysodium
import pymongo


class MDBCluster:
    K_CFG_CONN = "mdb_connection"
    K_CFG_CONN_KEY = "key"
    K_CFG_CONN_NONCE = "nonce"
    K_CFG_CONN_VAL = "value"

    def __init__(self, cfg_path="mdb_cluster.json", cfg_enc="utf-8"):
        self.cfg_path = cfg_path
        self.cfg_enc = cfg_enc
        self.conn = None  # connection to cluster

    def connect(self):
        conn_cfg = self._read_config()[MDBCluster.K_CFG_CONN]
        key = bytes(conn_cfg[MDBCluster.K_CFG_CONN_KEY],
                    self.cfg_enc)
        nonce = bytes(
            conn_cfg[MDBCluster.K_CFG_CONN_NONCE], self.cfg_enc)
        val = bytes(
            conn_cfg[MDBCluster.K_CFG_CONN_VAL], self.cfg_enc)
        conn_str = pysodium.crypto_secretbox_open(val, nonce, key)
        self.conn = pymongo.MongoClient(conn_str)

    def get_database(self, name):
        return self.conn[name]

    def set_connection(self, conn_str: str):
        cfg = self._read_config()
        key = pysodium.randombytes(pysodium.crypto_secretbox_KEYBYTES)
        nonce = pysodium.randombytes(pysodium.crypto_secretbox_NONCEBYTES)
        econn = pysodium.crypto_secretbox(conn_str, nonce, key)
        cfg[MDBCluster.K_CFG_CONN] = {
            MDBCluster.K_CFG_CONN_KEY: key.decode(self.cfg_enc),
            MDBCluster.K_CFG_CONN_NONCE: nonce.decode(self.cfg_enc),
            MDBCluster.K_CFG_CONN_VAL: econn.decode(self.cfg_enc)
        }
        self._write_config(cfg)

    def _read_config(self):
        return json.loads(self.cfg_path)

    def _write_config(self, cfg: dict):
        with open(self.cfg_path, "w") as f:
            f.write(json.dumps(cfg, indent=3))


class Collection:
    def __init__(self, cluster: MDBCluster, db_name: str, name: str):
        self.collection = cluster.get_database(db_name)[name]

    def _create_index(self):
        raise NotImplementedError

    def _insert(self, doc: dict):
        self.collection.insert_one(doc)
        self._create_index()


class AuthenticationCollection(Collection):
    K_USERNAME = "username"  # backend username per person / group (searchable)
    K_PASSWORD = "password"  # encrypted password

    def __init__(self, cluster: MDBCluster, db_name="album", name="authentication"):
        super.__init__(cluster, db_name, name)

    def add_user(self, username: str, password: str):
        if self.has_user(username):
            raise ValueError("username already exists")
        self._insert({
            AuthenticationCollection.K_USERNAME: username,
            AuthenticationCollection.K_PASSWORD: bson.Binary(pysodium.crypto_pwhash_str(
                password, pysodium.crypto_pwhash_OPSLIMIT_MODERATE, pysodium.crypto_pwhash_MEMLIMIT_MODERATE))
        })

    def verify_user(self, username: str, password: str):
        doc = self.collection.find_one(
            {AuthenticationCollection.K_USERNAME: username})
        if doc is None:
            raise ValueError("user does not exist")
        return pysodium.crypto_pwhash_str_verify(doc[AuthenticationCollection.K_PASSWORD], password)

    def has_user(self, username: str):
        return self.collection.find_one({AuthenticationCollection.K_USERNAME: username}) is not None

    def _create_index(self):
        if AuthenticationCollection.K_USERNAME not in self.collection.index_information():
            self.collection.create_index(
                [(AuthenticationCollection.K_USERNAME, pymongo.TEXT)], unique=True, background=True)


class MediaCollection(Collection):
    K_USERNAME = "username"  # unique id for user/group/project (searchable)
    K_TITLE = "title"  # title of media (searchable)
    K_TAG = "tag"  # tags for media (potentially limited)
    K_TYPE = "type"  # data type (link, text, image, video, sound) (searchable)
    K_DATA = "data"  # binary data of the media
    K_LINK = "link"  # link to external file sharing (unsupported or too large)
    K_LIKE = "like"  # likes of media (number or list of usernames)
    K_COMMENT = "comment"  # comments on media

    def __init__(self, cluster: MDBCluster, db_name="album", name="media"):
        super.__init__(cluster, db_name, name)

    def _create_index(self):
        if MediaCollection.K_USERNAME not in self.collection.index_information():
            self.collection.create_index(
                [(MediaCollection.K_USERNAME, pymongo.ASCENDING),
                 (MediaCollection.K_TITLE, pymongo.ASCENDING),
                 (MediaCollection.K_TYPE, pymongo.ASCENDING),
                 (MediaCollection.K_TAG, pymongo.ASCENDING)], unique=False, background=True)
            self.collection.create_index(
                [(MediaCollection.K_USERNAME, pymongo.TEXT),
                 (MediaCollection.K_TITLE, pymongo.TEXT),
                 (MediaCollection.K_TYPE, pymongo.TEXT)], unique=False, background=True)


# user/group/project settings & public objects
# project requires separate private collaborative spaces, implemented as group messages
# project timeline is the public-facing shared published media
class ProfileCollection(Collection):
    K_USERNAME = "username"  # unique id for user/group/project (searchable)
    K_PERMISSION = "permission"  # usernames with enumerated profile editing permissions
    K_TITLE = "title"  # display title for the profile (searchable)
    K_DESC = "description"  # flavor text displayed on profile
    K_TIMELINE = "timeline"  # list of paired text and media ids or other timeline objects
    K_COLLECTION = "collection"  # list of titled ordered lists of media ids
    K_TAG = "tag"  # histogram of tags of posts
    K_TAG_FILTER = "tag_filter"  # profiles to blacklist for tags

    def __init__(self, cluster: MDBCluster, db_name="album", name="profile"):
        super.__init__(cluster, db_name, name)

    def _create_index(self):
        if ProfileCollection.K_USERNAME not in self.collection.index_information():
            self.collection.create_index(
                [(ProfileCollection.K_USERNAME, pymongo.ASCENDING)], unique=True, background=True)
            self.collection.create_index(
                [(ProfileCollection.K_USERNAME, pymongo.TEXT), (ProfileCollection.K_TITLE, pymongo.TEXT)], unique=False, background=True)


class RelationshipCollection(Collection):
    K_USERNAME = "username"  # unique id for user (searchable)
    K_FRIEND = "friend"  # unique friend usernames
    K_PROJECT = "project"  # unique project usernames
    K_GROUP = "group"  # unique group usernames
    K_MSG = "msg"  # message ids user belongs to
    K_ALBUM = "album"  # album ids user follows
    K_LIKE = "like"  # list of liked media ids

    def __init__(self, cluster: MDBCluster, db_name="album", name="relationship"):
        super.__init__(cluster, db_name, name)

    def _create_index(self):
        if AuthenticationCollection.K_USERNAME not in self.collection.index_information():
            self.collection.create_index(
                [(AuthenticationCollection.K_USERNAME, pymongo.ASCENDING)], unique=True, background=True)
