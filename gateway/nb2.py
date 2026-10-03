"""Verificación nb2 del gateway (F4) — credenciales validadas ON-CANISTER.

La credencial `nb2.<principal>.<expiry>.<epoch>.<nonce>.<tag>` la emite el
canister `access` y la valida él mismo (``verify_credential(text) -> bool``).
El secreto HMAC que firma el `tag` vive SOLO en el canister: el gateway NO lo
conoce, y por eso no puede validar la firma localmente — tiene que llamar al
canister por query anónima.

Esto es la frontera de seguridad del plano de datos: si el gateway no puede
alcanzar el canister o la respuesta no es un `(bool)` bien formado, RECHAZA
(fail-closed). Nunca acepta por defecto ni "caché" una credencial que el
canister no haya confirmado.

Port fiel de `platforms/nebulock.py` del gateway Hermes (el wire format CBOR +
candid ya verificado contra réplica dfx 0.32), extraído aquí como módulo
autónomo sin dependencia de `gateway.config`.

Regla dura (igual que en atestación): sin réplica configurada o con réplica
caída → False. La autenticación de una petición de chat no degrada a
"permitir".
"""

from __future__ import annotations

import binascii
import re
import time
from typing import Callable, Optional

# ------------------------------------------------------------------ constantes

# Credencial nb2.* : tag = HMAC-SHA256 completo en hex (32 bytes = 64 hex).
_NB2_RE = re.compile(
    r"^nb2\.([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*)\.(\d{1,20})\.(\d{1,20})\.(\d{1,20})\.([0-9a-fA-F]{64})$"
)

_NB2_USER_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")

# Réplica/localhost por defecto (dfx local). En despliegue se apunta al
# boundary/mainnet vía NEBULOCK_NB2_REPLICA.
DEFAULT_REPLICA = "http://127.0.0.1:4943"

# TTL de caché (s): positiva 5s (SLA post-revoke: run-5 HUNT-A-01 — una
# ventana de 60s dejaba acceso post-revocación; 5s limita la ventana sin
# re-consultar por ráfaga), negativa 10s (mitiga fuerza bruta).
POSITIVE_CACHE_TTL = 5
NEGATIVE_CACHE_TTL = 10
CACHE_MAX = 512

# Transporte de red: (url, envelope_bytes) -> bytes del body de respuesta CBOR.
# Devuelve None o lanza para indicar fallo (→ False). Inyectable para tests.
Transport = Callable[[str, bytes], Optional[bytes]]


# ------------------------------------------------------------------ parseo

def parse_nb2_credential(token: str) -> Optional[dict]:
    """Parsea `nb2.*` → dict o None si el formato no cuadra (aditivo, sin red)."""
    m = _NB2_RE.match((token or "").strip())
    if not m:
        return None
    who, expiry, ep, nonce, tag = m.groups()
    try:
        return {
            "who": who,
            "expiry": int(expiry),
            "epoch": int(ep),
            "nonce": int(nonce),
            "tag": tag.lower(),
        }
    except ValueError:
        return None


def is_valid_user(value: object) -> bool:
    """Shape estricto del principal en `X-Nebulock-User` (header-injection safe).

    Solo `[A-Za-z0-9._-]{1,64}`. El frontend aplica la misma regla antes de
    enviar la cabecera.
    """
    return isinstance(value, str) and _NB2_USER_RE.match(value) is not None


# ------------------------------------------------------------------ LEB128

def _leb128_u(n: int) -> bytes:
    out = bytearray()
    n = int(n)
    if n < 0:
        raise ValueError("leb128_u con negativo")
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            break
    return bytes(out)


def _leb128_i(n: int) -> bytes:
    out = bytearray()
    n = int(n)
    while True:
        b = n & 0x7F
        n >>= 7
        sign = b & 0x40
        if (n == 0 and not sign) or (n == -1 and sign):
            out.append(b)
            break
        out.append(b | 0x80)
    return bytes(out)


def _leb128_u_decode(buf: bytes, pos: int):
    n, shift = 0, 0
    while True:
        b = buf[pos]
        pos += 1
        n |= (b & 0x7F) << shift
        if not (b & 0x80):
            return n, pos
        shift += 7
        if shift > 63:
            raise ValueError("leb128 desbordado")


def _leb128_i_decode(buf: bytes, pos: int):
    n, shift, size = 0, 0, 0
    while True:
        b = buf[pos]
        pos += 1
        size += 1
        n |= (b & 0x7F) << shift
        shift += 7
        if not (b & 0x80):
            if b & 0x40:
                n -= 1 << shift
            return n, pos
        if size > 10:
            raise ValueError("sleb128 desbordado")


# ------------------------------------------------------------------ CBOR

def _cbor_encode(value) -> bytes:
    """CBOR mínimo (solo lo que necesita el envelope de query a réplica)."""
    if isinstance(value, bool):
        return b"\xf5" if value else b"\xf4"
    if isinstance(value, int):
        if value >= 0:
            if value < 24:
                return bytes([value])
            if value < 256:
                return b"\x18" + value.to_bytes(1, "big")
            if value < 65536:
                return b"\x19" + value.to_bytes(2, "big")
            if value < 4294967296:
                return b"\x1a" + value.to_bytes(4, "big")
            return b"\x1b" + value.to_bytes(8, "big")
        v = -1 - value
        if v < 24:
            return bytes([0x20 | v])
        if v < 256:
            return b"\x38" + v.to_bytes(1, "big")
        if v < 65536:
            return b"\x39" + v.to_bytes(2, "big")
        if v < 4294967296:
            return b"\x3a" + v.to_bytes(4, "big")
        return b"\x3b" + v.to_bytes(8, "big")
    if isinstance(value, bytes):
        n = len(value)
        if n < 24:
            return bytes([0x40 | n]) + value
        if n < 256:
            return b"\x58" + bytes([n]) + value
        if n < 65536:
            return b"\x59" + n.to_bytes(2, "big") + value
        return b"\x5a" + n.to_bytes(4, "big") + value
    if isinstance(value, str):
        raw = value.encode()
        n = len(raw)
        if n < 24:
            return bytes([0x60 | n]) + raw
        if n < 256:
            return b"\x78" + bytes([n]) + raw
        if n < 65536:
            return b"\x79" + n.to_bytes(2, "big") + raw
        return b"\x7a" + n.to_bytes(4, "big") + raw
    if isinstance(value, dict):
        out = bytearray()
        n = len(value)
        if n < 24:
            out.append(0xA0 | n)
        elif n < 256:
            out += b"\xa8" + bytes([n])
        else:
            raise ValueError("cbor map too large")
        for k in sorted(value.keys(), key=lambda x: _cbor_encode(x)):
            out += _cbor_encode(k) + _cbor_encode(value[k])
        return bytes(out)
    raise ValueError(f"cbor: tipo no soportado {type(value).__name__}")


def _cbor_decode(buf: bytes, pos: int = 0):
    if pos >= len(buf):
        raise ValueError("cbor: fin inesperado")
    ib = buf[pos]
    pos += 1
    mt, ai = ib >> 5, ib & 0x1F
    if ai < 24:
        arg = ai
    elif ai == 24:
        if pos >= len(buf):
            raise ValueError("cbor: fin inesperado")
        arg = buf[pos]
        pos += 1
    elif ai == 25:
        arg = int.from_bytes(buf[pos:pos + 2], "big")
        pos += 2
    elif ai == 26:
        arg = int.from_bytes(buf[pos:pos + 4], "big")
        pos += 4
    elif ai == 27:
        arg = int.from_bytes(buf[pos:pos + 8], "big")
        pos += 8
    elif ai == 31:
        # Tamaño indefinido: solo arrays/mapas (réplica: signatures[]).
        if mt == 4:
            out = []
            while True:
                if pos >= len(buf):
                    raise ValueError("cbor: fin inesperado")
                if buf[pos] == 0xFF:
                    pos += 1
                    break
                v, pos = _cbor_decode(buf, pos)
                out.append(v)
            return out, pos
        if mt == 5:
            out = {}
            while True:
                if pos >= len(buf):
                    raise ValueError("cbor: fin inesperado")
                if buf[pos] == 0xFF:
                    pos += 1
                    break
                k, pos = _cbor_decode(buf, pos)
                v, pos = _cbor_decode(buf, pos)
                out[k] = v
            return out, pos
        raise ValueError("cbor: tamaño indefinido no soportado")
    else:
        raise ValueError("cbor: ai reservado")
    if mt == 0:
        return arg, pos
    if mt == 1:
        return -1 - arg, pos
    if mt == 2:
        return bytes(buf[pos:pos + arg]), pos + arg
    if mt == 3:
        return bytes(buf[pos:pos + arg]).decode(), pos + arg
    if mt == 4:
        out = []
        for _ in range(arg):
            v, pos = _cbor_decode(buf, pos)
            out.append(v)
        return out, pos
    if mt == 5:
        out = {}
        for _ in range(arg):
            k, pos = _cbor_decode(buf, pos)
            v, pos = _cbor_decode(buf, pos)
            out[k] = v
        return out, pos
    if mt == 6:
        # Tag (la réplica antepone 0xD9D9F7 = self-described CBOR): se ignora.
        return _cbor_decode(buf, pos)
    if mt == 7:
        if ib == 0xF6 or ib == 0xF7:
            return None, pos
        if ib in (0xF4, 0xF5):
            return ib == 0xF5, pos
        raise ValueError(f"cbor: simple {ib:#x} no soportado")
    raise ValueError(f"cbor: major {mt} no soportado")


# ------------------------------------------------------------------ principal

def principal_bytes(text: str) -> bytes:
    """Texto de principal → bytes del canister id (formato IC verificado).

    textual = base32(CRC32(body) || body), big-endian, sin padding:
    4 bytes CRC32 primero + cuerpo. Longitud en chars ≡ 0 mod 8 salvo
    7/15/23/... (relleno base32 '=' omitido).
    """
    alphabet = "abcdefghijklmnopqrstuvwxyz234567"
    val = {c: i for i, c in enumerate(alphabet)}
    clean = (text or "").strip().replace("-", "").lower()
    if not clean or any(c not in val for c in clean):
        raise ValueError("principal inválido")
    if clean == "aaaaaaa":  # management canister: cuerpo vacío, CRC32(b"")==0
        return b""
    nchars = len(clean)
    if nchars % 8 not in (0, 2, 4, 5, 7):
        raise ValueError("principal inválido")
    bits = "".join(f"{val[c]:05b}" for c in clean)
    excess = len(bits) % 8
    if excess:
        if not bits.endswith("0" * excess):
            raise ValueError("principal inválido")
        bits = bits[:len(bits) - excess]
    raw = int(bits, 2).to_bytes(len(bits) // 8, "big") if bits else b""
    if len(raw) < 5:  # 4 CRC + ≥1 byte (anónimo: b"\x04")
        raise ValueError("principal inválido")
    chk, body = raw[:4], raw[4:]
    if (binascii.crc32(body) & 0xFFFFFFFF) != int.from_bytes(chk, "big"):
        raise ValueError("principal inválido")
    return body


# ------------------------------------------------------------------ candid

def candid_text_arg(text: str) -> bytes:
    """Codifica un argumento Candid `(text)` sin libs externas.

    Primitivos van INLINE como índice SLEB128 negativo; tabla de tipos VACÍA:
    `DIDL 00 01 71 <len:leb128> <utf8>` (verificado contra candid 0.10.35).
    """
    payload = text.encode()
    return b"DIDL" + _leb128_u(0) + _leb128_u(1) + _leb128_i(-15) + _leb128_u(len(payload)) + payload


def candid_decode_bool(blob: bytes) -> bool:
    """Decodifica una respuesta Candid `(bool)`; estricta o excepción."""
    if len(blob) < 6 or blob[:4] != b"DIDL":
        raise ValueError("respuesta no-DIDL")
    pos = 4
    ntypes = blob[pos]
    pos += 1
    if ntypes != 0:
        raise ValueError("respuesta con tipos inesperados")
    nargs = blob[pos]
    pos += 1
    if nargs != 1:
        raise ValueError("respuesta con nargs inesperados")
    opcode, pos = _leb128_i_decode(blob, pos)
    if opcode != -2:  # bool
        raise ValueError("respuesta no-bool")
    if blob[pos] not in (0, 1):
        raise ValueError("bool inválido")
    return blob[pos] == 1


# ------------------------------------------------------------------ query

def nb2_query_envelope(canister_text: str, method: str, arg: bytes) -> bytes:
    """Envelope CBOR de query anónima a la réplica (sin firma)."""
    canister = principal_bytes(canister_text)
    expiry = (int(time.time()) + 300) * 1_000_000_000
    content = {
        "request_type": "query",
        "sender": b"\x04",
        "canister_id": canister,
        "method_name": method,
        "arg": arg,
        "ingress_expiry": expiry,
    }
    return _cbor_encode({"content": content})


def _default_transport(url: str, envelope: bytes) -> Optional[bytes]:
    """POST real vía requests con fallback a urllib. None/exception → False."""
    try:
        import requests  # type: ignore
    except ImportError:
        requests = None  # type: ignore
    if requests is not None:
        r = requests.post(
            url,
            data=envelope,
            headers={"Content-Type": "application/cbor"},
            timeout=1.0,
        )
        if r.status_code != 200:
            return None
        return r.content
    import urllib.request

    req = urllib.request.Request(
        url, data=envelope, headers={"Content-Type": "application/cbor"}, method="POST"
    )
    with urllib.request.urlopen(req, timeout=1.0) as r:
        if getattr(r, "status", 200) != 200:
            return None
        return r.read()


def nb2_call_verify_credential(
    replica: str,
    canister_text: str,
    token: str,
    transport: Optional[Transport] = None,
) -> bool:
    """Llama a `verify_credential(text) -> (bool)` por query anónima.

    Fail-closed: cualquier fallo de red/codificación/decode → False.
    """
    try:
        envelope = nb2_query_envelope(canister_text, "verify_credential", candid_text_arg(token))
    except Exception:
        return False
    base = (replica or "").strip().rstrip("/") or DEFAULT_REPLICA
    url = base + "/api/v2/canister/" + canister_text.strip() + "/query"
    try:
        data = (transport or _default_transport)(url, envelope)
    except Exception:
        return False
    if not data:
        return False
    try:
        reply, _ = _cbor_decode(bytes(data))
        blob = reply.get("reply", {}).get("arg") if isinstance(reply, dict) else None
        if not isinstance(blob, bytes):
            return False
        return candid_decode_bool(blob)
    except Exception:
        return False


# ------------------------------------------------------------------ gate

class Nb2Gate:
    """Frontera de autenticación nb2 del gateway: estructura + on-canister.

    - Estructura: la credencial debe parsear y su `who` debe coincidir con el
      principal de la cabecera `X-Nebulock-User` (si no, se aceptaría la
      credencial de A para hablar como B).
    - On-canister: delega la firma en `access.verify_credential`. Si la réplica
      no responde o responde mal, rechaza.
    - Caché: positiva corta (5s, SLA post-revoke run-5) y negativa corta (10s)
      para no re-consultar por ráfaga ni abrir fuerza bruta.
    """

    def __init__(
        self,
        canister_id: str,
        replica: str = DEFAULT_REPLICA,
        transport: Optional[Transport] = None,
        positive_ttl: int = POSITIVE_CACHE_TTL,
        negative_ttl: int = NEGATIVE_CACHE_TTL,
        now: Optional[Callable[[], float]] = None,
    ) -> None:
        self.canister_id = canister_id
        self.replica = replica
        self.transport = transport
        self.positive_ttl = positive_ttl
        self.negative_ttl = negative_ttl
        self._now = now or time.monotonic
        self._pos: dict[str, float] = {}
        self._neg: dict[str, float] = {}

    def _cache(self, table: dict[str, float], key: str, ttl: int) -> bool:
        t = table.get(key)
        if t is not None and self._now() - t <= ttl:
            return True
        if t is not None:
            table.pop(key, None)
        return False

    def authenticate(self, credential: str, user: str) -> bool:
        cred = (credential or "").strip()
        parsed = parse_nb2_credential(cred)
        if parsed is None:
            return False
        if not is_valid_user(user):
            return False
        if parsed["who"] != user:
            # La credencial pertenece a otro principal: rechazo sin consultar.
            return False
        key = cred
        if self._cache(self._pos, key, self.positive_ttl):
            return True
        if self._cache(self._neg, key, self.negative_ttl):
            return False
        ok = nb2_call_verify_credential(
            self.replica, self.canister_id, cred, transport=self.transport
        )
        self._prune()
        (self._pos if ok else self._neg)[key] = self._now()
        return ok

    def _prune(self) -> None:
        if len(self._pos) + len(self._neg) <= CACHE_MAX:
            return
        # Borrado conservador: se limpia el negativo (más efímero) primero.
        if self._neg:
            self._neg.clear()
        else:
            self._pos.clear()
