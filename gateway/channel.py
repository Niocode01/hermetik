"""Canal cifrado (F4, ADR-01 paso 5) — AES-GCM con subclaves direccionales.

El handshake (`attest_server.py` + `session.ts`) deja una clave MAESTRA de
sesión en ambos extremos. Este módulo es lo que hace ESA clave: deriva dos
subclaves HKDF (`hermetik/v1/c2s`, `hermetik/v1/s2c`) y cifra el tráfico del
plano de datos con AES-256-GCM, con un contador de secuencia por dirección que
va en el IV y además da anti-replay.

Por qué dos claves (run-5 HUNT-B-01): con una sola clave y contadores tx/rx
independientes, el seq=1 del cliente y el seq=1 del servidor compartían
(clave, nonce) — AES-GCM con nonce reutilizado pierde confidencialidad e
integridad. Con una clave por dirección, cada (clave, nonce) se usa una sola
vez aunque los contadores coincidan en número.

Espejo EXACTO de `sealMessage`/`openMessage` de `session.ts`:

  IV  = 4 bytes del contador (big-endian) + 8 bytes a cero
  ct  = AES-256-GCM(subclave_dir, IV, plaintext) → base64 (incluye tag de 16 B)

Interop byte a byte contra WebCrypto: se prueba en `test_channel.py` con Node
(`channel_interop.mjs`). Cualquier divergencia en el IV o en el orden del tag
rompería el canal al primer mensaje.
"""

from __future__ import annotations

import base64

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAX_SEQ = 2**32 - 1


def seal_message(key: bytes, seq: int, plaintext: str) -> str:
    """Cifra un mensaje. `seq` debe ser estrictamente creciente por dirección."""
    if len(key) != 32:
        raise ValueError("la clave de sesión debe medir 32 bytes")
    if not (0 < seq <= MAX_SEQ):
        raise ValueError("seq fuera de rango (0 < seq <= 2^32-1)")
    iv = seq.to_bytes(4, "big") + b"\x00" * 8
    ct = AESGCM(key).encrypt(iv, plaintext.encode(), None)
    return base64.b64encode(ct).decode()


def open_message(key: bytes, seq: int, sealed: str) -> str:
    """Descifra un mensaje. Lanza si el tag no valida o el seq es inválido."""
    if len(key) != 32:
        raise ValueError("la clave de sesión debe medir 32 bytes")
    if not (0 < seq <= MAX_SEQ):
        raise ValueError("seq fuera de rango (0 < seq <= 2^32-1)")
    iv = seq.to_bytes(4, "big") + b"\x00" * 8
    try:
        raw = base64.b64decode(sealed, validate=True)
    except Exception as exc:
        raise ValueError("sealed no es base64 válido") from exc
    pt = AESGCM(key).decrypt(iv, raw, None)
    return pt.decode()


class Channel:
    """Un canal de mensajes cifrados con subclaves por dirección.

    `seal` cifra con la subclave de envío; `open` descifra con la de recepción
    y exige un contador estrictamente creciente (anti-replay). Direcciones
    separadas POR CLAVE (run-5 B-01): aunque emisor y receptor coincidan en
    número de seq, los nonces nunca colisionan porque las claves difieren.

    Roles: el cliente se construye con `role="client"` (tx=c2s, rx=s2c); el
    servidor con `role="server"` (tx=s2c, rx=c2s).
    """

    def __init__(self, master_key: bytes, role: str = "client") -> None:
        if len(master_key) != 32:
            raise ValueError("la clave maestra de sesión debe medir 32 bytes")
        if role not in ("client", "server"):
            raise ValueError("role debe ser 'client' o 'server'")
        from attest_server import derive_directional_keys

        c2s, s2c = derive_directional_keys(master_key)
        if role == "client":
            self._tx_key, self._rx_key = c2s, s2c
        else:
            self._tx_key, self._rx_key = s2c, c2s
        self._tx_seq = 0
        self._rx_seq = 0

    def seal(self, plaintext: str) -> dict:
        self._tx_seq += 1
        return {"seq": self._tx_seq, "sealed": seal_message(self._tx_key, self._tx_seq, plaintext)}

    def open(self, seq: int, sealed: str) -> str:
        if seq <= self._rx_seq:
            raise ValueError(
                f"seq {seq} no es estrictamente creciente (último {self._rx_seq}): replay rechazado"
            )
        plaintext = open_message(self._rx_key, seq, sealed)
        self._rx_seq = seq
        return plaintext
