import base64
import bson
import json
import pysodium
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

    def __init__(self, cfg_path: str = "mdb_cluster.json"):
        self.cfg_path = cfg_path
        self.conn = None  # connection to cluster

    def connect(self) -> None:
        conn_cfg: ConnectionConfig = self._read_config()[ClusterClient.K_CFG_CONN]
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
        self._write_config(
            ConnectionConfig(
                key=base64.b64encode(key),
                nonce=base64.b64encode(nonce),
                value=base64.b64encode(econn),
            )
        )

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


class WeightedValue(TypedDict):
    value: str  # value of interest
    weight: float  # associated weight


class Document(TypedDict):
    _id: NotRequired[bson.ObjectId]  # unique document id
    # arbitrary labeled metrics (utility for all docs)
    metrics: list[WeightedValue]


class CollectionClient:
    def __init__(self, database: DatabaseClient, name: str):
        self.collection: mdb_c.Collection[type[Document]] = database.get_collection(
            name
        )

    def get_collection(self) -> mdb_c.Collection[type[Document]]:
        return self.collection

    def _create_indices(self) -> None:
        raise NotImplementedError

    def _insert(self, doc: type[Document]) -> None:
        self.collection.insert_one(doc)
        self._create_indices()


class AccountStatusEnum(IntEnum):
    ACTIVE = 0
    DEACTIVATED = auto()
    BANNED = auto()


class AccountStatusRecord(TypedDict):
    status: AccountStatusEnum  # account status
    timestamp: int  # timestamp in seconds


class AuthRecord(TypedDict):
    ip: str  # ip of client when authenticated
    timestamp: int  # timestamp in seconds


class AuthDocument(Document):
    userid: str  # unique user id (searchable)
    password: bson.Binary  # encrypted password
    authrecs: list[AuthRecord]  # history of logins (may be time-bound)
    statusrecs: list[AccountStatusRecord]  # history of account statuses


# TODO: only work with already encrypted passwords (maybe not, plaintext may be encrypted over HTTPS?)
class AuthCollectionClient(CollectionClient):
    def __init__(self, database: DatabaseClient, name: str = "authentication"):
        super().__init__(database, name)

    def add_user(self, doc: AuthDocument, password: str) -> None:
        if self.has_user(doc["userid"]):
            raise ValueError("userid already exists")
        doc["password"] = pysodium.crypto_pwhash_str(
            password,
            pysodium.crypto_pwhash_OPSLIMIT_MODERATE,
            pysodium.crypto_pwhash_MEMLIMIT_MODERATE,
        )
        self._insert(doc)

    def verify_user(self, userid: str, password: str) -> bool:
        doc: AuthDocument = self.collection.find_one({"userid": userid})
        if doc is None:
            raise ValueError("user does not exist")
        return bool(pysodium.crypto_pwhash_str_verify(doc["password"], password))

    def log_authentication(self, userid: str, ip: str) -> None:
        # TODO: update document .records
        raise NotImplementedError

    def has_user(self, userid: str) -> bool:
        return self.collection.find_one({"userid": userid}) is not None

    def _create_indices(self) -> None:
        if "userid" not in self.collection.index_information():
            self.collection.create_index(
                [("userid", mdb.ASCENDING)], unique=True, background=True
            )


class MediaTypeEnum(IntEnum):
    NONE = 0
    LINK = auto()
    TEXT = auto()
    IMAGE = auto()
    VIDEO = auto()
    SOUND = auto()


class UserValue(TypedDict):
    userid: str  # unique user id
    value: str  # value associated with user


# depending on which collection media is stored in, it may be used to generate albums
class MediaDocument(Document):
    credits: list[UserValue]  # userid and credit string
    title: str  # presented title
    tags: list[WeightedValue]  # tags for media (potentially limited)
    # data type (link, text, image, video, sound) (searchable)
    type: MediaTypeEnum
    uri: str  # uri (or uri suffix) to data on file server
    timestamp: int  # timestamp in seconds


# may have multiple media collections
# (help distribute load, order by type, order by visiibility/project/etc)
class MediaCollectionClient(CollectionClient):
    def add_media(self, doc: MediaDocument, obj: Any) -> None:
        # TODO: validation
        self._insert(doc)

    def _create_indices(self) -> None:
        if "credits" not in self.collection.index_information():
            self.collection.create_index(
                [
                    ("credits.userid", mdb.ASCENDING),
                    ("title", mdb.ASCENDING),
                    ("type", mdb.ASCENDING),
                    ("tags.value", mdb.ASCENDING),
                ],
                unique=False,
                background=True,
            )


class DocumentReference(TypedDict):
    collection: str  # mongodb collection name
    docid: bson.ObjectId  # document _id
    context: str  # arbitrary context for indexing/searching/etc


class EncryptedText(TypedDict):
    text: bson.Binary  # text, conditionally encrypted
    encrypted: bool  # true if encrypted (usually just for messaging channels)


# posts to profiles have public visbility/album access
# posts to message groups have private visibility and will not be in albums
class PostDocument(Document):
    userid: str  # user id belonging to publisher of post (user/project)
    title: str  # presented title of post
    text: EncryptedText  # conditionally encrypted
    media: list[DocumentReference]  # media documents, context is searchable
    timestamp: int  # timestamp in seconds
    reactions: dict[str, str]  # map of userid to reaction id (e.g. emoji name/code)
    # unique _ids of reply messages / post comments
    children: list[bson.ObjectId]
    parent: bson.ObjectId  # unique _id of message replied to / post commented on


# no default name, PostCollection made as needed
# all posts should not be lumped together
class PostCollectionClient(CollectionClient):
    def __init__(self, database: DatabaseClient, name: str):
        super.__init__(database, name)

    def add_post(self, doc: PostDocument) -> None:
        # TODO: validate message is real user
        # TODO: validate message is not empty
        self._insert(doc)

    def _create_indices(self) -> None:
        if "userid" not in self.collection.index_information():
            self.collection.create_index(
                [
                    ("userid", mdb.ASCENDING),
                    ("title", mdb.ASCENDING),
                    ("media.context", mdb.ASCENDING),
                ],
                unique=False,
                background=True,
            )
            self.collection.create_index(
                [
                    ("userid", mdb.TEXT),
                    ("title", mdb.TEXT),
                    ("media.context", mdb.TEXT),
                ],
                unique=False,
                background=True,
            )


class ChannelPermissionEnum(IntFlag):
    NONE = 0  # cannot access channel
    READ = auto()  # can read but not edit anything
    POST = auto()  # can make/update own posts
    POST_ADMIN = auto()  # POST with updating/deleting all posts
    BOARD = auto()  # can make/update own media boards
    BOARD_ADMIN = auto()  # BOARD with updating/deleting all media boards
    TITLE = auto()  # can edit channel title
    DESCRIPTION = auto()  # can edit channel description
    TAG = auto()  # can edit tag filter & only tags on all posts
    ADMIN = auto()  # all permissions, set user permissions, can delete channel


class MediaBoard(TypedDict):
    title: str
    description: str
    media: list[DocumentReference]  # media documents, context is for user use


class ChannelDocument(Document):
    userid: str  # userid of profile containing the channel
    permissions: dict[str, ChannelPermissionEnum]  # explicit user permissions
    defpermissions: ChannelPermissionEnum  # default user permissions (NONE for private channel)
    title: str
    description: str
    postcollection: str  # PostCollection name for channel posts
    mediaboards: list[MediaBoard]  # sets of user-collected media
    tags: list[WeightedValue]  # histogram of tag usage
    tagfilter: list[bson.ObjectId]  # docs excluded from tag histogram


# default collection name specified, reasonable to group all channel documents together
# channels associated with specific profile
class ChannelCollectionClient(CollectionClient):
    def __init__(self, database: DatabaseClient, name: str = "channels"):
        super.__init__(database, name)

    def add_channel(self, doc: ChannelDocument) -> None:
        # TODO: validation
        self._insert(doc)

    def _create_indices(self):
        if "userid" not in self.collection.index_information():
            self.collection.create_index(
                [("userid", mdb.ASCENDING)], unique=False, background=True
            )


class ProfilePermissionEnum(IntFlag):
    NONE = 0  # cannot access profile
    READ = auto()  # can read/view available channels
    CHANNEL = auto()  # can create own channels (upon which user is channel ADMIN)
    CHANNEL_ADMIN = auto()  # CHANNEL with mandatory ADMIN in all channels
    TITLE = auto()  # can edit profile title
    DESCRIPTION = auto()  # can edit profile description
    TAG = auto()  # can edit tag filter
    ADMIN = auto()  # all permissions, set user permissions, can delete profile


# has multiple Channels
class ProfileDocument(Document):
    userid: str  # may be unique id for user/group/project
    permissions: dict[str, ProfilePermissionEnum]  # user ids to permissions
    defpermissions: ProfilePermissionEnum  # default user permissions
    title: str
    description: str
    channels: list[DocumentReference]  # set of channels attached to profile
    tags: list[WeightedValue]  # histogram of tag usage across channels
    tagfilter: list[DocumentReference]  # channels excluded from tag histogram


# user/group/project settings & public objects
# project requires separate private collaborative spaces, implemented as group messages
# project timeline is the public-facing shared published media
# can have multiple collections, one each for users, groups, projects
class ProfileCollectionClient(CollectionClient):
    def __init__(self, database: DatabaseClient, name: str):
        super.__init__(database, name)

    def add_profile(self, doc: ProfileDocument) -> None:
        # TODO: validation
        self._insert(doc)

    def _create_indices(self) -> None:
        if "userid" not in self.collection.index_information():
            self.collection.create_index(
                [("userid", mdb.ASCENDING), ("title", mdb.ASCENDING)],
                unique=True,
                background=True,
            )
            self.collection.create_index(
                [("userid", mdb.TEXT), ("title", mdb.TEXT)],
                unique=False,
                background=True,
            )


class RelationDocument(Document):
    userid: str  # unique userid
    followers: list[str]  # set of unique user userids following the user
    follows: list[str]  # set of unique user/group/project userids user follows
    projects: list[str]  # all project userids user has worked on
    currprojects: list[str]  # current project userids user is working on
    groups: list[str]  # set of unique group profile userids user belongs to
    messages: list[DocumentReference]  # set of channels used for messaging
    albums: list[DocumentReference]  # set of album references user follows
    reactions: list[DocumentReference]  # post references with reaction context


class RelationCollectionClient(CollectionClient):
    def __init__(self, database: DatabaseClient, name: str = "relationship"):
        super.__init__(database, name)

    def add_relation(self, doc: RelationDocument) -> None:
        # TODO: validation
        self._insert(doc)

    def _create_indices(self):
        if "userid" not in self.collection.index_information():
            self.collection.create_index(
                [("userid", mdb.ASCENDING)], unique=True, background=True
            )


class AlbumDocument(Document):
    title: str  # unique presented title of album
    tags: list[WeightedValue]  # tag use/relevance (indexable)
    text: str  # text body of album description
    media: list[DocumentReference]  # media references, context for future
    reactions: dict[str, str]  # map of userid to reaction id (e.g. emoji name/code)


class AlbumCollectionClient(CollectionClient):
    def __init__(self, database: DatabaseClient, name: str = "album"):
        super.__init__(database, name)

    def add_album(self, doc: AlbumDocument) -> None:
        # TODO: validation
        self._insert(doc)

    def _create_indices(self):
        if "title" not in self.collection.index_information():
            self.collection.create_index(
                [("title", mdb.ASCENDING)], unique=True, background=True
            )
