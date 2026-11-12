"""AES primitives used only by executable preparation."""


def decrypt(data: bytes, key: bytes, iv: bytes | None, mode: str) -> bytes:
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    except ImportError as error:
        raise ValueError("AES preparation requires cryptography; run tools/ps3_to_ps3exe.py with uv") from error
    cipher_mode = {"cbc": modes.CBC, "ctr": modes.CTR, "ecb": lambda _: modes.ECB()}[mode](iv)
    context = Cipher(algorithms.AES(key), cipher_mode).decryptor()
    return context.update(data) + context.finalize()
