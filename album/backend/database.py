import base64
import bson
import cv2
import json
import pysodium
import numpy as np
import pymongo as mdb
import pymongo.collection as mdb_c
import pymongo.database as mdb_d
from enum import auto, IntEnum, IntFlag
from typing_extensions import TypedDict, NotRequired, Any


class ConnectionConfig(TypedDict):
    key: bytes
    nonce: bytes
    value: bytes


class ClusterClient:
    K_CFG_CONN = "mdb_connection"

    def __init__(self, cfg_path="mdb_cluster.json"):
        self.cfg_path = cfg_path
        self.conn = None  # connection to cluster

    def connect(self) -> None:
        conn_cfg: ConnectionConfig = self._read_config()[
            ClusterClient.K_CFG_CONN]
        key = base64.b64decode(conn_cfg["key"])
        nonce = base64.b64decode(conn_cfg["nonce"])
        econn = base64.b64decode(conn_cfg["value"])
        conn_str = pysodium.crypto_secretbox_open(econn, nonce, key)
        self.conn = mdb.MongoClient(conn_str)

    def get_database(self, name: str) -> mdb_d.Database:
        return self.conn[name]

    def set_connection(self, conn_str: str) -> None:
        key = pysodium.randombytes(pysodium.crypto_secretbox_KEYBYTES)
        nonce = pysodium.randombytes(pysodium.crypto_secretbox_NONCEBYTES)
        econn = pysodium.crypto_secretbox(conn_str, nonce, key)
        self._write_config(ConnectionConfig(
            key=base64.b64encode(key),
            nonce=base64.b64encode(nonce),
            value=base64.b64encode(econn)))

    def _read_config(self) -> dict:
        return json.loads(self.cfg_path)

    def _write_config(self, conn_cfg: ConnectionConfig) -> None:
        cfg = self._read_config()
        cfg[ClusterClient.K_CFG_CONN] = conn_cfg
        with open(self.cfg_path, "w") as f:
            f.write(json.dumps(cfg, indent=3))


class DatabaseClient:
    def __init__(self, cluster: ClusterClient, name="album"):
        self.database = cluster.get_database(name)

    def get_collection(self, name: str) -> mdb_c.Collection:
        return self.database[name]


class Document(TypedDict):
    _id: NotRequired[bson.ObjectId]  # unique document id


class CollectionClient:
    def __init__(self, database: DatabaseClient, name: str):
        self.collection: mdb_c.Collection[type[Document]] = database.get_collection(
            name)

    def _create_indices(self) -> None:
        raise NotImplementedError

    def _insert(self, doc: type[Document]) -> None:
        self.collection.insert_one(doc)
        self._create_indices()


class AuthDocument(Document):
    userid: str  # unique user id (searchable)
    password: bson.Binary  # encrypted password


class AuthCollectionClient(CollectionClient):
    def __init__(self, database: DatabaseClient, name="authentication"):
        super().__init__(database, name)

    def add_user(self, doc: AuthDocument, password: str) -> None:
        if self.has_user(doc["userid"]):
            raise ValueError("userid already exists")
        doc["password"] = pysodium.crypto_pwhash_str(
            password, pysodium.crypto_pwhash_OPSLIMIT_MODERATE, pysodium.crypto_pwhash_MEMLIMIT_MODERATE)
        self._insert(doc)

    def verify_user(self, userid: str, password: str) -> bool:
        doc: AuthDocument = self.collection.find_one({"userid": userid})
        if doc is None:
            raise ValueError("user does not exist")
        return bool(pysodium.crypto_pwhash_str_verify(doc["password"], password))

    def has_user(self, userid: str) -> bool:
        return self.collection.find_one({"userid": userid}) is not None

    def _create_indices(self) -> None:
        if "userid" not in self.collection.index_information():
            self.collection.create_index(
                [("userid", mdb.ASCENDING)], unique=True, background=True)


class MediaType(IntEnum):
    NONE = 0
    LINK = auto()
    TEXT = auto()
    IMAGE = auto()
    VIDEO = auto()
    SOUND = auto()


# depending on which collection media is stored in, it may be used to generate albums
# TODO: timestamp, investigate replacing all userid strings with bson.ObjectIds
class MediaDocument(Document):
    userids: set[str]  # set of unique user ids, source of media
    title: str  # presented title
    tags: set[str]  # tags for media (potentially limited)
    type: MediaType  # data type (link, text, image, video, sound) (searchable)
    data: bson.Binary  # binary data of the media


# TODO: timestamp
class MediaCollectionClient(CollectionClient):
    def __init__(self, database: DatabaseClient, name="media", str_enc="utf-8", img_ext=".png"):
        super.__init__(database, name)
        self.str_enc = str_enc
        self.img_ext = img_ext

    def add_media(self, doc: MediaDocument, obj) -> None:
        doc["data"] = bson.Binary(self._encode(doc["type"], obj))
        self._insert(doc)

    def _create_indices(self) -> None:
        if "userids" not in self.collection.index_information():
            self.collection.create_index(
                [("userids", mdb.ASCENDING),
                 ("title", mdb.ASCENDING),
                 ("type", mdb.ASCENDING),
                 ("tags", mdb.ASCENDING)], unique=False, background=True)

    def _decode(self, type: MediaType, bobj: bytes) -> Any:
        if type == MediaType.NONE:
            return None
        elif type == MediaType.LINK or type == MediaType.TEXT:
            return bobj.decode(self.str_enc)
        elif type == MediaType.IMAGE:
            return cv2.imdecode(np.frombuffer(bobj, dtype=np.uint8))
        elif type == MediaType.VIDEO:
            raise NotImplementedError("VIDEO type decoding not implemented")
        elif type == MediaType.SOUND:
            raise NotImplementedError("SOUND type decoding not implemented")
        else:
            raise ValueError(
                f"invalid type {type} without any decoding method")

    def _encode(self, type: MediaType, obj) -> bytes | None:
        if type == MediaType.NONE:
            return None
        elif type == MediaType.LINK or type == MediaType.TEXT:
            return str(obj).encode(self.str_enc)
        elif type == MediaType.IMAGE:
            rv, arr = cv2.imencode(self.img_ext, obj)
            if not rv:
                raise ValueError(
                    f"failed to encode object as {self.img_ext} image")
            return bytes(arr)
        elif type == MediaType.VIDEO:
            raise NotImplementedError("VIDEO type encoding not implemented")
        elif type == MediaType.SOUND:
            raise NotImplementedError("SOUND type encoding not implemented")
        else:
            raise ValueError(
                f"invalid type {type} without any encoding method")


# posts to profiles have public visbility/album access
# posts to message groups have private visibility and will not be in albums
# TODO: timestamp
class PostDocument(Document):
    userid: str  # user id belonging to publisher of post
    title: str  # presented title of post
    text: str  # text body of post
    media: set[bson.ObjectId]  # unique _ids of media included in post
    reactions: dict[str, str]  # map of userid to reaction (emoji)
    # unique _ids of reply messages / post comments
    children: list[bson.ObjectId]
    parent: bson.ObjectId  # unique _id of message replied to / post commented on


# architecture requires one PostCollection per Profile and per Channel
#
# TODO: timestamp
class PostCollectionClient(CollectionClient):
    def __init__(self, database: DatabaseClient, name="post",):
        super.__init__(database, name)

    def add_post(self, doc: PostDocument) -> None:
        # TODO: validate message is real user
        # TODO: validate message is not empty
        self._insert(doc)

    def _create_indices(self) -> None:
        if "userid" not in self.collection.index_information():
            self.collection.create_index(
                [("userid", mdb.ASCENDING),
                 ("title", mdb.ASCENDING)], unique=False, background=True)
            self.collection.create_index(
                [("userid", mdb.TEXT),
                 ("title", mdb.TEXT)], unique=False, background=True)


class ProfilePermissionType(IntFlag):
    NONE = 0  # cannot access profile
    READ = auto()  # can read but not edit anything
    POST = auto()  # can make posts and update own posts
    POST_ADMIN = auto()  # WRITE with updating/deleting other users posts
    COLLECT = auto()  # can make collections and and update own collections
    COLLECT_ADMIN = auto()  # COLLECT with updating/deleting other users collections
    DESCRIPTION = auto()  # can edit profile description
    ADMIN = auto()  # can do everything, including set other users' permissions


# TODO: maybe replace list of post document _ids with single post collection name
# timeline uses PostCollection with name that should use userid, e.g. timeline::<userid>
class ProfileDocument(Document):
    userid: str  # may be unique id for user/group/project
    permissions: dict[str, ProfilePermissionType]  # user ids to permissions
    defpermissions: ProfilePermissionType  # default user permissions
    title: str
    description: str
    # list of root post unique _ids published on timeline (not including comments)
    timeline: list[bson.ObjectId]
    collections: dict[str, set[bson.ObjectId]]  # labeled sets of media _ids
    tags: dict[str, float]  # histogram of tag usage
    tag_filter: set[str]  # unique userids to prevent from influencing tags


# user/group/project settings & public objects
# project requires separate private collaborative spaces, implemented as group messages
# project timeline is the public-facing shared published media
class ProfileCollectionClient(CollectionClient):
    def __init__(self, database: DatabaseClient, name="profile"):
        super.__init__(database, name)

    def add_profile(self, doc: ProfileDocument) -> None:
        # TODO: validation
        self._insert(doc)

    def _create_indices(self) -> None:
        # TODO: investigate mongodb unique=True for compound index
        if "userid" not in self.collection.index_information():
            self.collection.create_index(
                [("userid", mdb.ASCENDING),
                 ("title", mdb.ASCENDING)], unique=True, background=True)
            self.collection.create_index(
                [("userid", mdb.TEXT),
                 ("title", mdb.TEXT)], unique=False, background=True)


# TODO: investigate replacing reactions with set and custom hash function
class RelationDocument(Document):
    userid: str
    friends: set[str]  # set of unique user userids
    prevprojects: set[str]  # set of project profile userids user has worked on
    currprojects: set[str]  # set of project profile userids user is working on
    groups: set[str]  # set of unique group profile userids user belongs to
    messages: set[bson.ObjectId]  # set of channel document object _ids
    albums: set[bson.ObjectId]  # set of album document object _ids
    # list of profiles, post _id that was reacted to, and reaction
    reactions: list[tuple[str, bson.ObjectId, str]]


class RelationCollectionClient(CollectionClient):
    def __init__(self, database: DatabaseClient, name="relationship"):
        super.__init__(database, name)

    def add_relation(self, doc: RelationDocument) -> None:
        # TODO: validation
        self._insert(doc)

    def _create_indices(self):
        if "userid" not in self.collection.index_information():
            self.collection.create_index(
                [("userid", mdb.ASCENDING)], unique=True, background=True)


class ChannelPermissionType(IntFlag):
    NONE = 0  # cannot access profile
    READ = auto()  # can read but not edit anything
    POST = auto()  # can make posts and update own posts
    POST_ADMIN = auto()  # WRITE with updating/deleting other users posts
    DESCRIPTION = auto()  # can edit profile description
    ADMIN = auto()  # can do everything, including set other users' permissions


# TODO: maybe do not organize messages hierarchically like a profile
# TODO: this may be handled by front end, we'll have to see if backend hampers it
# TODO: maybe replace list of post document _ids with single post collection name
# post collection may use some name that involves Channel document _id
class ChannelDocument(Document):
    userids: set[str]  # set of unique user userids in message room
    permissions: dict[str, ChannelPermissionType]  # user ids to permissions
    defpermissions: ChannelPermissionType  # default user permissions
    title: str
    description: str
    # list of root post unique _ids published on timeline (not including comments)
    timeline: list[bson.ObjectId]


class ChannelCollectionClient(CollectionClient):
    def __init__(self, database: DatabaseClient, name="channel"):
        super.__init__(database, name)

    def add_channel(self, doc: ChannelDocument) -> None:
        # TODO: validation
        self._insert(doc)

    def _create_indices(self):
        # TODO: check mongodb behavior with unique=False with multi-key index
        if "userids" not in self.collection.index_information():
            self.collection.create_index(
                [("userids", mdb.ASCENDING)], unique=False, background=True)
