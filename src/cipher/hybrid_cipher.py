from typing import Tuple, List, Generator
from Cryptodome.Random import get_random_bytes
from cryptography.hazmat.primitives import padding

from .AES import AESCipher
from .DES import DESCipher
from .blowfish import BlowfishCipher
from .abstract_cipher import Cipher

def round_robin_cipher(ciphers: List[Cipher]) -> Generator[Cipher, None, None]:
    """
    Round robin cipher

    Parameters
    ----------
    ciphers: List[Cipher]
        List of ciphers

    Returns
    -------
    Generator[Cipher, None, None]
        Generator of ciphers which yields a cipher in round robin fashion
    """
    while True:
        for cipher in ciphers:
            yield cipher

class HybridEncrypter:
    """
    Hybrid encrypter class
    """

    @staticmethod
    def encrypt(raw: bytes) -> Tuple[bytes, bytes]:
        """
        Encrypt raw data using hybrid encryption

        Parameters
        ----------
        raw: bytes
            Raw data

        Returns
        -------
        Tuple[bytes, bytes]
            Encrypted data and keys used for encryption (AES key (16 bytes)
            + Blowfish key (16 bytes) + DES key (8 bytes))
        """

        chunk_size = 16

        key_aes = get_random_bytes(16)
        key_blowfish = get_random_bytes(16)
        key_des = get_random_bytes(8)

        aes = AESCipher(key_aes)
        des = DESCipher(key_des)
        blowfish = BlowfishCipher(key_blowfish)

        cipher_generator = round_robin_cipher([aes, blowfish, des])

        # Use PKCS#7 padding
        padder = padding.PKCS7(chunk_size * 8).padder()
        padded_raw = padder.update(raw) + padder.finalize()

        encrypted_data = b""
        for i in range(0, len(padded_raw), chunk_size):
            chunk = padded_raw[i : i + chunk_size]
            encrypted_data += next(cipher_generator).encrypt(chunk)

        return (encrypted_data, key_aes + key_blowfish + key_des)

    @staticmethod
    def decrypt(encrypted_data: bytes, keys: bytes) -> bytes:
        """
        Decrypt encrypted data

        Parameters
        ----------
        encrypted_data: bytes
            Encrypted data
        keys: bytes
            Keys used for encryption (AES key (16 bytes)
            + Blowfish key (16 bytes) + DES key (8 bytes))

        Returns
        -------
        bytes
            Decrypted data
        """

        chunk_size = 16

        key_aes = keys[:16]
        key_blowfish = keys[16:32]
        key_des = keys[32:]

        aes = AESCipher(key_aes)
        blowfish = BlowfishCipher(key_blowfish)
        des = DESCipher(key_des)

        cipher_generator = round_robin_cipher([aes, blowfish, des])

        decrypted_data = b""
        for i in range(0, len(encrypted_data), chunk_size):
            chunk = encrypted_data[i : i + chunk_size]
            decrypted_data += next(cipher_generator).decrypt(chunk)

        # Remove padding using PKCS#7
        unpadder = padding.PKCS7(chunk_size * 8).unpadder()
        unpadded_data = unpadder.update(decrypted_data)

        return unpadded_data
