import base64
import hashlib
from typing import Union

from Crypto import Random
from Crypto.Cipher import AES


# me
class AESCipherV2:
    def __init__(self, key: str):
        self.__bs = AES.block_size
        self.__key = hashlib.sha256(key.encode("utf-8")).digest()

    def encrypt(self, plaintext: str) -> str:
        """
        평문 str --> base64 기반의 암호화된 str
        """
        padded_bytes = self.__pad(plaintext).encode("utf-8")
        iv = Random.new().read(self.__bs)

        cipher = AES.new(self.__key, AES.MODE_CBC, iv)
        encrypted_bytes = cipher.encrypt(padded_bytes)

        return base64.b64encode(iv + encrypted_bytes).decode("utf-8")

    def decrypt(self, ciphertext: str) -> str:
        """
        base64 기반의 암호화된 str --> 평문 str
        """
        decoded_bytes = base64.b64decode(ciphertext.encode("utf-8"))
        iv, encrypted_bytes = decoded_bytes[: self.__bs], decoded_bytes[self.__bs :]

        cipher = AES.new(self.__key, AES.MODE_CBC, iv)
        decrypted_bytes = cipher.decrypt(encrypted_bytes)

        return self.__unpad(decrypted_bytes).decode("utf-8")

    def __pad(self, s: str) -> str:
        padding = self.__bs - len(s) % self.__bs
        return s + padding * chr(padding)

    @staticmethod
    def __unpad(s: bytes) -> bytes:
        return s[: -ord(s[len(s) - 1 :])]


# Dana
class AESCipher:
    def __init__(self, keytext: str):
        self.bs = AES.block_size
        self.key = hashlib.sha256(keytext.encode()).digest()

    def encrypt(self, plaintext: str) -> bytes:
        """
        평문을 base64 형식의 bytes로 암호화한다.
        :param plaintext: 평문 str
        :return: 암호화된 base64 bytes
        """
        raw = self._pad(plaintext)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(raw.encode()))

    def decrypt(self, encrypted: Union[bytes, str]) -> str:
        """
        base64 형식으로 암호화된 데이터를 str으로 복호화한다.
        :param encrypted: base64 형식의 bytes 또는 str
        :return: 복호화된 str
        """
        enc = base64.b64decode(encrypted)
        iv = enc[: AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return self._unpad(cipher.decrypt(enc[AES.block_size :])).decode("utf-8")

    def _pad(self, s: str) -> str:
        return s + (self.bs - len(s) % self.bs) * chr(self.bs - len(s) % self.bs)

    @staticmethod
    def _unpad(s: bytes) -> bytes:
        return s[: -ord(s[len(s) - 1 :])]
