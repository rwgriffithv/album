import cv2
import numpy as np
from typing_extensions import Any


from database import MediaTypeEnum


# TODO: make file server read and write operations for processing media
class MediaClient:
    def __init__(self, str_enc: str = "utf-8", img_ext: str = "png"):
        self.str_enc = str_enc
        self.img_ext = img_ext

    def get(self, uri: str) -> Any:
        raise NotImplementedError("retrieval of media files not yet implemented")
    
    def decode(self, type: MediaTypeEnum, bobj: bytes) -> Any:
        if type == MediaTypeEnum.NONE:
            return None
        elif type == MediaTypeEnum.LINK or type == MediaTypeEnum.TEXT:
            return bobj.decode(self.str_enc)
        elif type == MediaTypeEnum.IMAGE:
            return cv2.imdecode(np.frombuffer(bobj, dtype=np.uint8))
        elif type == MediaTypeEnum.VIDEO:
            raise NotImplementedError("VIDEO type decoding not implemented")
        elif type == MediaTypeEnum.SOUND:
            raise NotImplementedError("SOUND type decoding not implemented")
        else:
            raise ValueError(f"invalid type {type} without any decoding method")

    def encode(self, type: MediaTypeEnum, obj: Any) -> bytes | None:
        if type == MediaTypeEnum.NONE:
            return None
        elif type == MediaTypeEnum.LINK or type == MediaTypeEnum.TEXT:
            return str(obj).encode(self.str_enc)
        elif type == MediaTypeEnum.IMAGE:
            rv, arr = cv2.imencode(self.img_ext, obj)
            if not rv:
                raise ValueError(f"failed to encode object as {self.img_ext} image")
            return bytes(arr)
        elif type == MediaTypeEnum.VIDEO:
            raise NotImplementedError("VIDEO type encoding not implemented")
        elif type == MediaTypeEnum.SOUND:
            raise NotImplementedError("SOUND type encoding not implemented")
        else:
            raise ValueError(f"invalid type {type} without any encoding method")
