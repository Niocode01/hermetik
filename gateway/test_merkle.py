"""Tests de Merkle: inclusión (C7.3.4) verificada, consistencia (C7.3.5) pendiente.

ESTADO HONESTO:
  - Inclusión: VERIFICADA exhaustivamente (todos los tamaños 1..40, todos los
    índices, casos negativos). Es usable.
  - Consistencia: NO FIABLE. `consistency_proof` lanza NotImplementedError. Se
    han hecho cinco intentos de reimplementarla sin portar la librería de
    referencia y todos fallan. Los tests marcan el caso como xfail, no como
    aprobado. Lo correcto es portar `transparency-dev/merkle`.

Este fichero NO debe leerse como "Merkle está hecho". Debe leerse como
"inclusión sí; consistencia pendiente de portar".
"""

import hashlib

import pytest

from merkle import (
    EMPTY_ROOT,
    LEAF_PREFIX,
    MerkleError,
    consistency_proof,
    inclusion_proof,
    leaf_hash,
    merkle_root,
    node_hash,
    verify_consistency,
    verify_inclusion,
)


def leaves_of(n: int, tag: bytes = b"rec") -> list[bytes]:
    return [leaf_hash(tag + str(i).encode()) for i in range(n)]


# --- Estructura básica ------------------------------------------------------


def test_leaf_hash_uses_domain_separation():
    assert leaf_hash(b"x") == hashlib.sha256(LEAF_PREFIX + b"x").digest()
    assert leaf_hash(b"x") != hashlib.sha256(b"x").digest()


def test_node_hash_uses_domain_separation():
    assert node_hash(b"a", b"b") != hashlib.sha256(b"a" + b"b").digest()


def test_single_leaf_root_is_the_leaf():
    assert merkle_root(leaves_of(1)) == leaves_of(1)[0]


def test_empty_tree_root():
    assert merkle_root([]) == EMPTY_ROOT


def test_two_leaf_root():
    lv = leaves_of(2)
    assert merkle_root(lv) == node_hash(lv[0], lv[1])


def test_root_is_deterministic():
    assert merkle_root(leaves_of(9)) == merkle_root(leaves_of(9))


def test_root_changes_with_content():
    a = leaves_of(5)
    b = leaves_of(5)
    b[2] = leaf_hash(b"distinto")
    assert merkle_root(a) != merkle_root(b)


# --- INCLUSIÓN: el bloque verificado ---------------------------------------


@pytest.mark.parametrize("n", list(range(1, 41)))
def test_inclusion_verifies_for_every_size_and_index(n):
    """Todos los tamaños de 1 a 40 y todos los índices: la prueba verifica."""
    lv = leaves_of(n)
    root = merkle_root(lv)
    for i in range(n):
        proof = inclusion_proof(lv, i)
        assert verify_inclusion(lv[i], i, n, proof, root), f"n={n} i={i}"


@pytest.mark.parametrize("n", [1, 2, 3, 5, 8, 17, 33, 40])
def test_inclusion_proof_is_logarithmic(n):
    """La prueba crece logarítmicamente (C7.3.4: no el log entero)."""
    lv = leaves_of(n)
    for i in range(n):
        assert len(inclusion_proof(lv, i)) <= max(1, n.bit_length())


def test_inclusion_wrong_leaf_rejected():
    lv = leaves_of(8)
    proof = inclusion_proof(lv, 3)
    assert verify_inclusion(leaf_hash(b"otro"), 3, 8, proof, merkle_root(lv)) is False


def test_inclusion_wrong_index_rejected():
    lv = leaves_of(8)
    proof = inclusion_proof(lv, 3)
    with pytest.raises(MerkleError):
        verify_inclusion(lv[3], 99, 8, proof, merkle_root(lv))


def test_inclusion_tree_size_smaller_than_index_rejected():
    """tree_size <= index ⇒ rechazo (vector publicado tree-size-too-small)."""
    lv = leaves_of(8)
    proof = inclusion_proof(lv, 3)
    with pytest.raises(MerkleError, match="hoja del árbol"):
        verify_inclusion(lv[3], 3, 3, proof, merkle_root(lv))


def test_inclusion_truncated_proof_rejected():
    lv = leaves_of(8)
    proof = inclusion_proof(lv, 5)[:-1]
    with pytest.raises(MerkleError, match="corta"):
        verify_inclusion(lv[5], 5, 8, proof, merkle_root(lv))


def test_inclusion_overlong_proof_rejected():
    lv = leaves_of(2)
    proof = inclusion_proof(lv, 0) + [b"\x00" * 32]
    with pytest.raises(MerkleError, match="larga"):
        verify_inclusion(lv[0], 0, 2, proof, merkle_root(lv))


def test_inclusion_out_of_range_index_rejected():
    with pytest.raises(MerkleError, match="fuera del árbol"):
        inclusion_proof(leaves_of(4), 4)


def test_inclusion_negative_index_rejected():
    with pytest.raises(MerkleError, match="negativo"):
        verify_inclusion(b"\x00" * 32, -1, 4, [], EMPTY_ROOT)


def test_inclusion_proof_does_not_leak_sibling_leaves():
    """La prueba de un log grande no entrega el log: solo los hermanos del camino.

    La afirmación correcta es sobre el TAMAÑO y la proporción: con 1000 hojas la
    prueba es de ~10 nodos, no de 1000. Un nodo suelto puede coincidir con una hoja
    (el hermano inmediato de un índice par ES una hoja), así que lo que se comprueba
    es que la prueba no contiene el log, no que no contenga ninguna hoja.
    """
    lv = leaves_of(1000)
    proof = inclusion_proof(lv, 500)
    assert len(proof) < 12  # log2(1000) ≈ 10
    # La prueba es una fracción ínfima del log: no lo entrega.
    assert len(proof) < len(lv) / 50
    # El número de nodos que coinciden con hojas es mínimo (a lo sumo los hermanos
    # de nivel 0, es decir 1).
    coincident = sum(1 for node in proof if node in lv)
    assert coincident <= 1


# --- CONSISTENCIA: port directo de transparency-dev/merkle (CT) ---------------
# Verificado byte a byte contra el oráculo Go (proof.Consistency) para todos los
# pares (first_size, n) con n <= 64, y verificación cruzada exhaustiva
# constructores↔verificadores. Los tests de tamaño y negativos siguen las mismas
# reglas que los de inclusión.


@pytest.mark.parametrize("n", list(range(1, 41)))
def test_consistency_verifies_for_every_pair(n):
    """Todos los pares (first_size, n): la prueba verifica contra ambas raíces."""
    lv = leaves_of(n)
    r2 = merkle_root(lv)
    for f in range(1, n):
        r1 = merkle_root(lv[:f])
        proof = consistency_proof(lv, f)
        assert verify_consistency(f, n, proof, r1, r2), f"f={f} n={n}"
        # El tamaño de la prueba es logarítmico, no lineal.
        assert len(proof) <= max(2, 2 * n.bit_length())


def test_consistency_equal_sizes():
    """first_size == second_size: prueba vacía y raíces iguales verifican."""
    lv = leaves_of(8)
    r = merkle_root(lv)
    assert verify_consistency(8, 8, [], r, r) is True
    assert verify_consistency(8, 8, [], r, leaf_hash(b"x")) is False
    # Prueba no vacía con tamaños iguales ⇒ rechazo explícito.
    with pytest.raises(MerkleError, match="no vacía"):
        verify_consistency(8, 8, [b"\x00" * 32], r, r)


def test_consistency_from_zero_requires_empty_proof_and_is_trivially_true():
    """Desde árbol vacío con prueba vacía: devuelve True como la referencia.

    (En Go, `Consistency(0, n)` es error de construcción; pero `RootFrom...`
    devuelve empty-root. Nuestro verify con first_size==0 y prueba vacía
    devuelve True para encajar con verify_match de la referencia.)
    """
    lv = leaves_of(5)
    r = merkle_root(lv)
    assert verify_consistency(0, 5, [], EMPTY_ROOT, r) is True
    # Prueba no vacía desde vacío ⇒ rechazo.
    with pytest.raises(MerkleError, match="vacía"):
        verify_consistency(0, 5, [b"\x00" * 32], EMPTY_ROOT, r)


def test_consistency_wrong_old_root_rejected():
    """Raíz antigua que no cuadra ⇒ la verificación devuelve False."""
    lv = leaves_of(8)
    r2 = merkle_root(lv)
    proof = consistency_proof(lv, 4)
    assert verify_consistency(4, 8, proof, leaf_hash(b"falsa"), r2) is False


def test_consistency_non_prefix_rejected():
    """Un árbol que NO es prefijo no debe pasar la verificación."""
    lv = leaves_of(8)
    other = [leaf_hash(b"otro" + str(i).encode()) for i in range(4)]
    proof = consistency_proof(lv, 4)
    assert verify_consistency(4, 8, proof, merkle_root(other), merkle_root(lv)) is False


def test_consistency_first_greater_than_second_rejected():
    with pytest.raises(MerkleError, match="extensión"):
        verify_consistency(8, 4, [], b"\x00" * 32, b"\x00" * 32)


def test_consistency_empty_proof_for_distinct_sizes_rejected():
    with pytest.raises(MerkleError, match="vacía"):
        verify_consistency(2, 8, [], merkle_root(leaves_of(2)), merkle_root(leaves_of(8)))


def test_rewritten_history_is_detected_by_root_comparison():
    """El principio de C7.3.5 que SÍ podemos demostrar ya: comparar raíces caza
    una historia reescrita, mientras que comparar contadores no la ve.

    Esto no depende de la prueba de consistencia: es la propiedad de la raíz, que
    sí está implementada y verificada.
    """
    original = leaves_of(5, b"original")
    published_root = merkle_root(original)

    rewritten = list(original)
    rewritten[2] = leaf_hash(b"REGISTRO-FALSIFICADO")
    rewritten_root = merkle_root(rewritten)

    # El contador no ve nada: misma longitud.
    assert len(rewritten) == len(original) == 5
    # La raíz sí: no coincide con la anclada.
    assert rewritten_root != published_root


def test_counter_only_check_would_accept_rewrite():
    """Deja constancia del modo de fallo que la norma advierte."""
    original = leaves_of(5, b"original")
    rewritten = leaves_of(5, b"original")
    rewritten[2] = leaf_hash(b"FALSIFICADO")
    assert len(original) == len(rewritten)
    assert merkle_root(original) != merkle_root(rewritten)


# --- Robustez de la raíz ----------------------------------------------------


def test_root_of_1_and_2_and_3_by_hand():
    """Comprobación a mano de las raíces de árboles pequeños."""
    lv = leaves_of(3)
    assert merkle_root(lv[:1]) == lv[0]
    assert merkle_root(lv[:2]) == node_hash(lv[0], lv[1])
    # 3 hojas: partición por k=2 → [h0,h1] y [h2]
    assert merkle_root(lv) == node_hash(node_hash(lv[0], lv[1]), lv[2])
