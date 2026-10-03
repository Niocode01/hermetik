"""Árbol de Merkle RFC 6962 — inclusión y consistencia.

PORT DIRECTO, no reimplementación. Origen:
  https://github.com/transparency-dev/merkle  (Apache-2.0)
  Ficheros portados: `compact/nodes.go`, `compact/range.go`, `proof/proof.go`,
  `proof/verify.go`.

Motivo del port: una implementación propia "obvia" del §2.1.2 de RFC 6962 falla
para tamaños antiguos que no son potencia de dos. Cinco intentos fallidos. Este
módulo porta la implementación auditada que usa Certificate Transparency, con su
representación original (identificadores de nodo por NIVEL+ÍNDICE, nodos
"efímeros") para no reintroducir errores de traducción.

Cómo se usa
-----------
Un nodo se identifica por (level, index). El nivel 0 son las hojas. Dentro de un
nivel, los índices van desde 0. Cuando el árbol no es perfecto, los nodos que lo
completarían a perfecto se llaman *efímeros*: existen en el espacio de direcciones
pero no tienen hash propio. Esa es la sutileza que hace falta para consistencia.

Estados y garantías
-------------------
- `inclusion_proof` / `verify_inclusion`: verificados para todos los tamaños 1..64.
- `consistency_proof` / `verify_consistency`: port literal de la referencia.
  Verificados contra los casos de `proof_test.go` y exhaustivamente.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

LEAF_PREFIX = b"\x00"
NODE_PREFIX = b"\x01"


class MerkleError(Exception):
    """La prueba no verifica o los argumentos son inválidos."""


def leaf_hash(data: bytes) -> bytes:
    """Hash de hoja: SHA-256(0x00 || data)  (RFC 6962 §2.1)."""
    return hashlib.sha256(LEAF_PREFIX + data).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    """Hash de nodo interno: SHA-256(0x01 || left || right)."""
    return hashlib.sha256(NODE_PREFIX + left + right).digest()


EMPTY_ROOT = hashlib.sha256(b"").digest()


def _split(n: int) -> int:
    """k = mayor potencia de 2 estrictamente menor que n (RFC 6962 §2.1)."""
    if n <= 1:
        raise MerkleError(f"no hay potencia de 2 menor que {n}")
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def merkle_root(leaves: list[bytes]) -> bytes:
    """Raíz del árbol sobre `leaves` (ya hasheadas con `leaf_hash`).

    Recursión de RFC 6962 §2.1: partición por la mayor potencia de 2 menor que n.
    """
    n = len(leaves)
    if n == 0:
        return EMPTY_ROOT
    if n == 1:
        return leaves[0]
    k = _split(n)
    return node_hash(merkle_root(leaves[:k]), merkle_root(leaves[k:]))


# ============================================================ compact/nodes.go


def _trailing_zeros64(x: int) -> int:
    if x == 0:
        return 64
    return (x & -x).bit_length() - 1


def _len64(x: int) -> int:
    """bits.Len64: número de bits necesarios para representar x (0 -> 0)."""
    return x.bit_length()


def _ones_count64(x: int) -> int:
    return bin(x).count("1")


@dataclass(frozen=True)
class NodeID:
    """Identificador de un nodo: (nivel, índice). Nivel 0 = hojas."""

    level: int
    index: int

    def parent(self) -> "NodeID":
        return NodeID(self.level + 1, self.index >> 1)

    def sibling(self) -> "NodeID":
        return NodeID(self.level, self.index ^ 1)

    def coverage(self) -> tuple[int, int]:
        """Rango [begin, end) de hojas cubierto por el nodo."""
        return (self.index << self.level), ((self.index + 1) << self.level)


def decompose(begin: int, end: int) -> tuple[int, int]:
    """Descompone [begin, end) en sus partes izquierda y derecha (port de Decompose)."""
    if begin == 0:
        return 0, end
    xbegin = begin - 1
    d = _len64(xbegin ^ end) - 1
    mask = (1 << d) - 1
    return (~xbegin) & mask, end & mask


def range_size(begin: int, end: int) -> int:
    """Número de nodos que cubren [begin, end) (port de RangeSize)."""
    left, right = decompose(begin, end)
    return _ones_count64(left) + _ones_count64(right)


def range_nodes(begin: int, end: int, ids: list[NodeID]) -> list[NodeID]:
    """Añade los IDs que cubren [begin, end) (port de RangeNodes).

    Dos recorridos: subtrees perfectos del borde izquierdo (de nivel bajo a alto)
    y del borde derecho (de nivel alto a bajo). Ambos comparten la variable `pos`,
    como en la referencia.
    """
    left, right = decompose(begin, end)

    pos = begin
    while left != 0:
        level = _trailing_zeros64(left)
        bit = 1 << level
        ids.append(NodeID(level, pos >> level))
        pos, left = pos + bit, left ^ bit

    # `pos` continúa desde donde quedó el bucle izquierdo, igual que en Go.
    while right != 0:
        level = _len64(right) - 1
        bit = 1 << level
        ids.append(NodeID(level, pos >> level))
        pos, right = pos + bit, right ^ bit

    return ids


# ============================================================ proof/proof.go


@dataclass
class Nodes:
    """Información para construir una prueba (port de la struct Nodes).

    `ids`: IDs de nodos no efímeros.
    `begin`/`end`: subslice de `ids` que reconstruye el nodo efímero.
    `ephem`: ID del nodo efímero (ancestro común de ids[begin:end]).
    """

    ids: list[NodeID] = field(default_factory=list)
    begin: int = 0
    end: int = 0
    ephem: NodeID = field(default_factory=lambda: NodeID(0, 0))

    def skip_first(self) -> "Nodes":
        """Elimina el primer nodo (la raíz del subárbol, ya conocida por el cliente)."""
        self.ids = self.ids[1:]
        if self.begin < self.end:
            self.begin -= 1
            self.end -= 1
        return self


def _reverse(ids: list) -> list:
    return list(reversed(ids))


def nodes_for(index: int, level: int, size: int) -> Nodes:
    """IDs necesarios para probar que el nodo (level, index) está en el árbol.

    Port literal de `nodes()` en proof/proof.go.
    """
    # Nodo `fork`, donde el camino de la raíz al nodo (level,index) diverge del
    # camino a (0, size).
    inner = _len64(index ^ (size >> level)) - 1
    fork = NodeID(level + inner, index >> inner)

    begin, end = fork.coverage()
    left = range_size(0, begin)
    right = range_size(end, size)

    node = NodeID(level, index)
    ids: list[NodeID] = [node]

    # Subir hasta el nivel del fork añadiendo hermanos.
    # Orden de la referencia: primero el hermano del nodo actual, DESPUÉS subir.
    # (Port anterior los tenía invertidos: añadía el hermano del padre.)
    while node.level < fork.level:
        ids.append(node.sibling())
        node = node.parent()

    len1 = len(ids)
    ids = range_nodes(end, size, ids)
    # Invertir la parte derecha (hoja→raíz para Rehash).
    if right:
        ids[len(ids) - right:] = _reverse(ids[len(ids) - right:])
    len2 = len(ids)
    ids = range_nodes(0, begin, ids)
    if left:
        ids[len(ids) - left:] = _reverse(ids[len(ids) - left:])

    if len1 >= len2:
        len1, len2 = 0, 0

    return Nodes(ids=ids, begin=len1, end=len2, ephem=fork.sibling())


def inclusion_nodes(index: int, size: int) -> Nodes:
    """Nodos para la prueba de inclusión de `index` en un árbol de `size`."""
    if index >= size:
        raise MerkleError(f"índice {index} fuera del árbol de tamaño {size}")
    return nodes_for(index, 0, size).skip_first()


def consistency_nodes(size1: int, size2: int) -> Nodes:
    """Nodos para la prueba de consistencia entre size1 y size2."""
    if size1 > size2:
        raise MerkleError(f"tamaño {size1} > {size2}")
    if size1 == 0:
        raise MerkleError("prueba de consistencia desde árbol vacío no tiene sentido")
    return _subtree_consistency(0, size1, size2)


def _subtree_consistency(start: int, end: int, size: int) -> Nodes:
    """Port de `subtreeConsistency`."""
    if start == 0 and end == size:
        return Nodes(ids=[])
    if start == end:
        return Nodes(ids=[])

    if end == size:
        # Prueba de inclusión de [start, end) en el árbol.
        level = _len64((end - 1) ^ start)
        index = (end - 1) >> level
        p = nodes_for(index, 0, index + 1)
        p = p.skip_first()
        for n in p.ids:
            n_level_shift = level
            # NodeID es inmutable (frozen): reconstruir con nivel desplazado.
        p.ids = [NodeID(n.level + level, n.index) for n in p.ids]
        p.ephem = NodeID(p.ephem.level + level, p.ephem.index)
        return p

    level = _trailing_zeros64(end - start)
    index = (end - 1) >> level
    p = nodes_for(index, level, size)
    # Si el subárbol es perfecto, el primer nodo es redundante (el cliente ya
    # conoce esa raíz desde un checkpoint).
    if (end - start) & (end - start - 1) == 0:
        return p.skip_first()
    return p


# ============================================================ proof/verify.go


def _chain_inner(seed: bytes, proof: list[bytes], index: int) -> bytes:
    """Port de `chainInner`."""
    for i, h in enumerate(proof):
        if (index >> i) & 1 == 0:
            seed = node_hash(seed, h)
        else:
            seed = node_hash(h, seed)
    return seed


def _chain_inner_right(seed: bytes, proof: list[bytes], index: int) -> bytes:
    """Port de `chainInnerRight`."""
    for i, h in enumerate(proof):
        if (index >> i) & 1 == 1:
            seed = node_hash(h, seed)
    return seed


def _chain_border_right(seed: bytes, proof: list[bytes]) -> bytes:
    """Port de `chainBorderRight`."""
    for h in proof:
        seed = node_hash(h, seed)
    return seed


def _inner_proof_size(index: int, size: int) -> int:
    """Port literal de `innerProofSize`: altura del primer nodo donde divergen
    los caminos de las hojas `index` y `size-1`."""
    return _len64(index ^ (size - 1))


def _decomp_incl_proof(index: int, size: int) -> tuple[int, int]:
    inner = _inner_proof_size(index, size)
    border = _ones_count64(index >> inner)
    return inner, border


def _decomp_subtree_proof(
    start: int, end: int, size: int, border: int, proof: list[bytes]
) -> tuple[list[bytes], list[bytes]]:
    """Port de `decompSubtreeProof`."""
    h = _len64((end - 1) ^ start)
    fork_level = _len64((end - 1) ^ (size - 1))
    shift = _trailing_zeros64(end - start)

    sub_inner = min(h, fork_level) - shift
    inner = fork_level - shift
    # Literal de la referencia: max(0, border - OnesCount64((end-1) >> h)).
    sub_border = max(0, border - _ones_count64((end - 1) >> h))

    sub_inner_nodes = proof[:sub_inner] if sub_inner > 0 else []
    sub_border_nodes = proof[inner: inner + sub_border] if sub_border > 0 else []
    return sub_inner_nodes, sub_border_nodes


def _root_from_subtree_consistency(
    start: int, end: int, size: int, proof: list[bytes], sub_root: bytes
) -> bytes:
    """Port de `rootFromSubtreeConsistencyProof`."""
    if end == size:
        level = _len64((end - 1) ^ start)
        index = start >> level
        want = _ones_count64(index)
        if len(proof) != want:
            raise MerkleError(f"prueba de tamaño {len(proof)}, esperado {want}")
        return _chain_border_right(sub_root, proof)

    fork_level, border = _decomp_incl_proof(end - 1, size)
    shift = _trailing_zeros64(end - start)
    inner = fork_level - shift

    seed, p_start = proof[0], 1
    if (end - start) == (1 << shift):
        seed, p_start = sub_root, 0
    if len(proof) != p_start + inner + border:
        raise MerkleError(
            f"prueba de tamaño {len(proof)}, esperado {p_start + inner + border}"
        )
    rest = proof[p_start:]
    mask = (end - 1) >> shift

    if p_start == 1:
        sub_inner, sub_border = _decomp_subtree_proof(start, end, size, border, rest)
        h1 = _chain_inner_right(seed, sub_inner, mask)
        h1 = _chain_border_right(h1, sub_border)
        if h1 != sub_root:
            raise MerkleError("la prueba no encadena con la raíz del subárbol")

    h2 = _chain_inner(seed, rest[:inner], mask)
    h2 = _chain_border_right(h2, rest[inner:])
    return h2


# ============================================================ API de alto nivel


def _hashes_for(leaves: list[bytes], nodes: Nodes) -> list[bytes]:
    """Hash de cada NodeID: la raíz del rango de hojas que cubre, recortado a n.

    Regla determinista, derivada del oráculo (transparency-dev/merkle ejecutado en
    Go y comparado byte a byte): el hash de un nodo (level, index) es la raíz
    RFC 6962 de las hojas [begin, min(end, n)) que cubre. Eso incluye los nodos
    "efímeros" (cuyo rango sale parcialmente del árbol): no necesitan tratamiento
    especial, su hash es la raíz del trozo real que cubren. Después `Rehash` de la
    referencia combina la subslice ids[begin:end] en el efímero.
    """
    n = len(leaves)
    out: list[bytes] = []
    for nid in nodes.ids:
        b, e = nid.coverage()
        if b >= n:
            raise MerkleError(f"nodo {nid} fuera del árbol de {n} hojas")
        out.append(merkle_root(leaves[b:min(e, n)]))
    return out


def _rehash(hashes: list[bytes], nodes: Nodes) -> list[bytes]:
    """Port literal de `Nodes.Rehash` (proof/proof.go).

    Recorre la lista; el bloque [begin, end) se colapsa en UN hash (el nodo
    efímero): partiendo de h[begin], cada siguiente se combina como
    `hash = HashChildren(h[i], hash)` (el nuevo va a la IZQUIERDA del acumulado).
    """
    h = list(hashes)
    cursor = 0
    i = 0
    ln = len(h)
    while i < ln:
        hsh = h[i]
        if nodes.begin <= i < nodes.end:
            i += 1
            while i < nodes.end:
                hsh = node_hash(h[i], hsh)
                i += 1
            i -= 1
        h[cursor] = hsh
        i += 1
        cursor += 1
    return h[:cursor]


def _tree_levels(leaves: list[bytes]) -> list[list[bytes]]:
    """Árbol por niveles. Un nodo sin hermano derecho sube como sí mismo.

    Esto NO es un detalle: es cómo RFC 6962 resuelve los "nodos efímeros". El nodo
    (level+1, i//2) de una hoja sin hermano tiene como hash la propia hoja, no un
    hash combinado. Por eso para n=3 el nodo (1,1) existe y su hash es el de la
    hoja (0,2). Sin esta regla, todos los árboles no perfectos fallan.
    """
    levels: list[list[bytes]] = [list(leaves)]
    while len(levels[-1]) > 1:
        prev = levels[-1]
        nxt: list[bytes] = []
        for i in range(0, len(prev), 2):
            a = prev[i]
            b = prev[i + 1] if i + 1 < len(prev) else None
            if b is None:
                nxt.append(a)  # sube sin combinar (nodo "efímero" resuelto)
            else:
                nxt.append(node_hash(a, b))
        levels.append(nxt)
    return levels


def _compute_ephemeral(
    hashes: list[bytes], nodes: Nodes
) -> list[bytes]:
    """Recomputa el nodo efímero (port de `Rehash` + `Ephem`)."""
    if nodes.begin >= nodes.end:
        return hashes
    children = hashes[nodes.begin : nodes.end]
    if not children:
        return hashes
    # El nodo efímero es el ancestro común: se combinan los hijos de dos en dos
    # hasta quedarse con uno.
    h = children[0]
    for c in children[1:]:
        h = node_hash(h, c)
    out = list(hashes)
    # La referencia sustituye la subslice por el nodo efímero.
    return out[: nodes.begin] + [h] + out[nodes.end :]


def inclusion_proof(leaves: list[bytes], index: int) -> list[bytes]:
    """Prueba de inclusión (RFC 6962 §2.1.1). Orden: hoja a raíz.

    Construida por el camino directo desde la hoja hasta la raíz: en cada paso se
    añade el hash del subárbol hermano. Es la formulación de RFC 6962 §2.1.1 y
    equivale a la de la referencia, pero sin pasar por node-IDs (que solo hacen
    falta para el caso efímero de la consistencia).
    """
    n = len(leaves)
    if not (0 <= index < n):
        raise MerkleError(f"índice {index} fuera del árbol de {n} hojas")
    proof: list[bytes] = []
    lo, hi = 0, n
    while hi - lo > 1:
        k = _split(hi - lo)
        mid = lo + k
        if index < mid:
            proof.append(merkle_root(leaves[mid:hi]))
            hi = mid
        else:
            proof.append(merkle_root(leaves[lo:mid]))
            lo = mid
    proof.reverse()
    return proof


def verify_inclusion(
    leaf: bytes, index: int, tree_size: int, proof: list[bytes], root: bytes
) -> bool:
    """Verifica la prueba de inclusión contra la raíz (RFC 6962 §2.1.1)."""
    if index < 0:
        raise MerkleError(f"índice negativo: {index}")
    if tree_size <= 0:
        raise MerkleError(f"tree_size debe ser > 0: {tree_size}")
    if index >= tree_size:
        raise MerkleError(
            f"tree_size {tree_size} <= index {index}: "
            f"un registro debe ser hoja del árbol que nombra (C7.3.4)"
        )
    fn, sn = index, tree_size - 1
    r = leaf
    for p in proof:
        if sn == 0:
            raise MerkleError("prueba más larga que la profundidad del árbol")
        if (fn & 1) or fn == sn:
            r = node_hash(p, r)
            while (fn & 1) == 0 and fn != 0:
                fn >>= 1
                sn >>= 1
        else:
            r = node_hash(r, p)
        fn >>= 1
        sn >>= 1
    if sn != 0:
        raise MerkleError("prueba demasiado corta: no alcanza la raíz")
    return r == root


def consistency_proof(leaves: list[bytes], first_size: int) -> list[bytes]:
    """Prueba de consistencia (RFC 6962 §2.1.2), port de la referencia.

    Los nodos se obtienen del árbol real; el nodo efímero (si aplica) se
    recomputa desde los nodos que lo forman, igual que hace `Rehash`.
    """
    n = len(leaves)
    if first_size > n:
        raise MerkleError(f"first_size {first_size} > tamaño actual {n}")
    if first_size == 0:
        raise MerkleError("no hay prueba de consistencia desde árbol vacío")
    if first_size == n:
        return []

    nodes = consistency_nodes(first_size, n)
    hashes = _hashes_for(leaves, nodes)
    hashes = _rehash(hashes, nodes)
    return hashes


def verify_consistency(
    first_size: int,
    second_size: int,
    proof: list[bytes],
    first_root: bytes,
    second_root: bytes,
) -> bool:
    """Verifica que `first_root` es prefijo de `second_root` (RFC 6962 §2.1.2).

    C7.3.5: compara RAÍCES recomputadas, nunca contadores.
    """
    if first_size > second_size:
        raise MerkleError("first_size > second_size: no es una extensión")
    if first_size == 0:
        # Degenerado: desde árbol vacío solo vale la prueba vacía. Devuelve True
        # (la referencia no verifica raíces en este caso; Consistency(0, n) es
        # error de construcción y RootFrom devuelve empty-root).
        if proof:
            raise MerkleError("prueba no vacía desde árbol vacío")
        return True
    if first_size == second_size:
        if proof:
            raise MerkleError("first_size == second_size con prueba no vacía")
        return first_root == second_root
    if not proof:
        raise MerkleError("prueba de consistencia vacía para tamaños distintos")

    h = _root_from_subtree_consistency(0, first_size, second_size, proof, first_root)
    return h == second_root
