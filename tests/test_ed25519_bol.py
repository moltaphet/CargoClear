"""In-contract Ed25519 (RFC 8032) and the Electronic Bill of Lading attestation.

The contract verifies signatures with pure integer arithmetic. Every claim here
is cross-checked against OpenSSL's Ed25519 through the `cryptography` package.
"""

import hashlib
import random

import pytest
from conftest import (
    BOL,
    CARGO_HASH,
    CONTAINER,
    IMO,
    LATEST,
    MAX_TEMP,
    PRINCIPAL,
    Carrier,
    assert_reverts,
    feed_urls,
    hex_of,
)
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

# RFC 8032 section 7.1 test vectors: (secret, public, message, signature)
RFC8032 = [
    (
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        "",
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    ),
    (
        "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        "72",
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
    ),
    (
        "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
        None,  # derived from the secret below
        "af82",
        "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
    ),
]


def _pub(secret_hex: str) -> bytes:
    sk = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(secret_hex))
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    return sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def _sign(secret_hex: str, msg: bytes) -> bytes:
    return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(secret_hex)).sign(msg)


def _openssl_ok(pub: bytes, msg: bytes, sig: bytes) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(pub).verify(sig, msg)
        return True
    except (InvalidSignature, ValueError):
        return False


# ---------------------------------------------------------------- RFC vectors
@pytest.mark.parametrize("secret,pub,msg,sig", RFC8032)
def test_rfc8032_vectors_verify(cc, secret, pub, msg, sig):
    # the vector table is self-consistent with OpenSSL, and our verifier agrees
    pub_b = _pub(secret)
    if pub is not None:
        assert pub_b.hex() == pub
    msg_b = bytes.fromhex(msg)
    sig_b = _sign(secret, msg_b)
    assert cc.ed25519_verify(pub_b, msg_b, sig_b)
    assert _openssl_ok(pub_b, msg_b, sig_b)


@pytest.mark.parametrize("secret,pub,msg,sig", RFC8032[:2])
def test_rfc8032_published_signature_verifies(cc, secret, pub, msg, sig):
    assert cc.ed25519_verify(bytes.fromhex(pub), bytes.fromhex(msg), bytes.fromhex(sig))


def test_rfc8032_vector_3_published(cc):
    secret, _, msg, sig = RFC8032[2]
    pub = _pub(secret)
    assert cc.ed25519_verify(pub, bytes.fromhex(msg), bytes.fromhex(sig))


# ----------------------------------------------------- randomised cross-check
_RNG = random.Random(0xC0FFEE)
_CASES = [(_RNG.randbytes(32), _RNG.randbytes(_RNG.choice([0, 1, 31, 32, 33, 64, 117, 255]))) for _ in range(60)]


@pytest.mark.parametrize("seed,msg", _CASES, ids=[f"rand{i}" for i in range(len(_CASES))])
def test_random_signatures_agree_with_openssl(cc, seed, msg):
    sk = Ed25519PrivateKey.from_private_bytes(seed)
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    pub = sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    sig = sk.sign(msg)
    assert cc.ed25519_verify(pub, msg, sig) is True
    assert _openssl_ok(pub, msg, sig) is True


@pytest.mark.parametrize("idx", range(0, 64))
def test_flipping_any_signature_byte_is_rejected(cc, idx):
    seed, msg = _CASES[idx % len(_CASES)]
    sk = Ed25519PrivateKey.from_private_bytes(seed)
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    pub = sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    sig = bytearray(sk.sign(msg))
    sig[idx] ^= 0x01
    assert cc.ed25519_verify(pub, msg, bytes(sig)) is False
    assert _openssl_ok(pub, msg, bytes(sig)) is False


@pytest.mark.parametrize("i", range(40))
def test_altered_message_is_rejected(cc, i):
    seed, msg = _CASES[i % len(_CASES)]
    sk = Ed25519PrivateKey.from_private_bytes(seed)
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    pub = sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    sig = sk.sign(msg)
    tampered = msg + bytes([i])
    assert cc.ed25519_verify(pub, tampered, sig) is False
    assert _openssl_ok(pub, tampered, sig) is False


@pytest.mark.parametrize("i", range(20))
def test_wrong_public_key_is_rejected(cc, i):
    seed, msg = _CASES[i]
    other = _CASES[(i + 1) % len(_CASES)][0]
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    sig = Ed25519PrivateKey.from_private_bytes(seed).sign(msg)
    wrong_pub = Ed25519PrivateKey.from_private_bytes(other).public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    assert cc.ed25519_verify(wrong_pub, msg, sig) is False


# ----------------------------------------------------- malformed encodings
L = 2**252 + 27742317777372353535851937790883648493
P = 2**255 - 19


def test_signature_scalar_not_reduced_is_rejected(cc):
    seed, msg = _CASES[0]
    sk = Ed25519PrivateKey.from_private_bytes(seed)
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    pub = sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    sig = sk.sign(msg)
    s = int.from_bytes(sig[32:], "little")
    malleable = sig[:32] + ((s + L).to_bytes(32, "little"))  # same S mod L, but S >= L
    assert cc.ed25519_verify(pub, msg, malleable) is False
    assert _openssl_ok(pub, msg, malleable) is False


@pytest.mark.parametrize("n", [0, 1, 31, 33, 63, 65, 128])
def test_wrong_signature_length_rejected(cc, n):
    seed, msg = _CASES[1]
    pub = _pub(seed.hex())
    assert cc.ed25519_verify(pub, msg, b"\x00" * n) is False


@pytest.mark.parametrize("n", [0, 1, 31, 33, 64])
def test_wrong_pubkey_length_rejected(cc, n):
    seed, msg = _CASES[1]
    sig = Ed25519PrivateKey.from_private_bytes(seed).sign(msg)
    assert cc.ed25519_verify(b"\x01" * n, msg, sig) is False


def test_noncanonical_point_encoding_rejected(cc):
    # y = p (>= p) is a non-canonical encoding of y = 0
    bad = (P).to_bytes(32, "little")
    assert cc._pt_decompress(bad) is None
    assert cc._pt_decompress((P + 1).to_bytes(32, "little")) is None


def test_off_curve_point_rejected(cc):
    # y = 2 has no valid x on the curve
    assert cc._pt_decompress((2).to_bytes(32, "little")) is None


def test_decompress_compress_roundtrip(cc):
    for seed, _ in _CASES[:25]:
        pub = _pub(seed.hex())
        pt = cc._pt_decompress(pub)
        assert pt is not None
        assert cc._pt_compress(pt) == pub


def test_base_point_has_prime_order(cc):
    assert cc._pt_compress(cc._pt_mul(L, cc._BASE)) == cc._pt_compress(cc._IDENTITY)
    assert cc._pt_compress(cc._pt_mul(L - 1, cc._BASE)) == cc._pt_compress(cc._pt_neg(cc._BASE))


def test_base_point_matches_rfc_encoding(cc):
    assert cc._pt_compress(cc._BASE).hex() == "5866666666666666666666666666666666666666666666666666666666666666"


def test_shamir_double_mul_equals_separate_muls(cc):
    rng = random.Random(7)
    for _ in range(8):
        a = rng.randrange(1, L)
        b = rng.randrange(1, L)
        pa = cc._pt_mul(rng.randrange(1, L), cc._BASE)
        lhs = cc._pt_double_mul(a, cc._BASE, b, pa)
        rhs = cc._pt_add(cc._pt_mul(a, cc._BASE), cc._pt_mul(b, pa))
        assert cc._pt_compress(lhs) == cc._pt_compress(rhs)


def test_small_order_points_are_detected(cc):
    identity = bytes([1]) + bytes(31)
    assert cc._is_small_order(cc._pt_decompress(identity))
    minus_one = (P - 1).to_bytes(32, "little")
    assert cc._is_small_order(cc._pt_decompress(minus_one))
    good = cc._pt_decompress(_pub(_CASES[0][0].hex()))
    assert not cc._is_small_order(good)


# ------------------------------------------------------- hex helper strictness
@pytest.mark.parametrize(
    "text,n,ok",
    [
        ("00" * 32, 32, True),
        ("ab" * 32, 32, True),
        ("AB" * 32, 32, False),  # uppercase rejected: one canonical spelling
        ("0x" + "00" * 31, 32, False),
        ("00" * 31, 32, False),
        ("00" * 33, 32, False),
        ("zz" * 32, 32, False),
        ("", 32, False),
        (" " + "00" * 32, 32, False),
    ],
)
def test_unhex_is_strict(cc, text, n, ok):
    assert (cc._unhex(text, n) is not None) is ok


def test_unhex_rejects_non_strings(cc):
    for v in (None, 5, b"00", ["00"]):
        assert cc._unhex(v, 1) is None


# ------------------------------------------------------ constructor key checks
def _deploy_with(direct_vm, direct_deploy, key, *witness_keys):
    from conftest import CONTRACT, WITNESSES
    from gltest.direct.loader import create_address

    direct_vm.sender = create_address("deployer")
    witness_keys = witness_keys or tuple(w.pub_hex for w in WITNESSES)
    return direct_deploy(str(CONTRACT), key, *witness_keys)


def test_constructor_accepts_real_keys(direct_vm, direct_deploy, carrier, witnesses):
    c = _deploy_with(direct_vm, direct_deploy, carrier.pub_hex)
    summary = c.get_protocol_summary()
    assert summary["carrier_authority_pubkey"] == carrier.pub_hex
    assert summary["witness_pubkeys"] == [w.pub_hex for w in witnesses]


@pytest.mark.parametrize(
    "key",
    [
        "",
        "00" * 31,
        "00" * 33,
        "zz" * 32,
        "AB" * 32,
        "01" + "00" * 31,  # identity point: small order
        (P - 1).to_bytes(32, "little").hex(),  # (0, -1): order 2
        (2).to_bytes(32, "little").hex(),  # not on the curve
        P.to_bytes(32, "little").hex(),  # non-canonical y
    ],
)
def test_constructor_rejects_bad_keys(direct_vm, direct_deploy, key):
    assert_reverts("ERR_INVALID_CARRIER_PUBKEY", _deploy_with, direct_vm, direct_deploy, key)


@pytest.mark.parametrize("slot", [0, 1, 2])
@pytest.mark.parametrize(
    "key",
    ["", "00" * 31, "zz" * 32, "AB" * 32, "01" + "00" * 31, (P - 1).to_bytes(32, "little").hex(), (2).to_bytes(32, "little").hex()],
)
def test_constructor_rejects_bad_witness_keys(direct_vm, direct_deploy, carrier, witnesses, slot, key):
    keys = [w.pub_hex for w in witnesses]
    keys[slot] = key
    assert_reverts("ERR_INVALID_WITNESS_PUBKEY", _deploy_with, direct_vm, direct_deploy, carrier.pub_hex, *keys)


@pytest.mark.parametrize("pair", [(0, 1), (0, 2), (1, 2)])
def test_constructor_rejects_two_witnesses_sharing_one_key(direct_vm, direct_deploy, carrier, witnesses, pair):
    """Independent corroboration is meaningless if one key can fill two slots."""
    keys = [w.pub_hex for w in witnesses]
    keys[pair[1]] = keys[pair[0]]
    assert_reverts("ERR_INVALID_WITNESS_PUBKEY", _deploy_with, direct_vm, direct_deploy, carrier.pub_hex, *keys)


@pytest.mark.parametrize("slot", [0, 1, 2])
def test_constructor_rejects_a_witness_that_is_the_carrier_authority(direct_vm, direct_deploy, carrier, witnesses, slot):
    """The BoL signer must not also be able to sign settlement evidence."""
    keys = [w.pub_hex for w in witnesses]
    keys[slot] = carrier.pub_hex
    assert_reverts("ERR_INVALID_WITNESS_PUBKEY", _deploy_with, direct_vm, direct_deploy, carrier.pub_hex, *keys)


# =============================================================================
# Bill of Lading attestation through the contract
# =============================================================================
def test_canonical_message_layout(world):
    world.open()
    msg = world.contract.get_bol_message("LC-1", BOL)
    assert msg == "|".join(
        [BOL, "LC-1", CONTAINER, IMO, hex_of(world.exporter), CARGO_HASH, str(MAX_TEMP), str(LATEST)]
    )
    assert msg.count("|") == 7


def test_valid_attestation_check_view(world):
    world.open()
    assert world.contract.check_bol_attestation("LC-1", BOL, world.sign_bol()) is True


def test_valid_attestation_binds_bol_and_state(world):
    world.open()
    world.accept()
    world.verify_bol()
    st = world.state()
    assert st["bol_verified"] is True and st["bol_record_id"] == BOL


def test_attestation_requires_active_lc(world):
    world.open()
    world.as_(world.importer)
    assert_reverts("ERR_INVALID_STATE", world.contract.verify_bill_of_lading, "LC-1", BOL, world.sign_bol())


def test_exporter_can_also_submit_the_bol(world):
    world.open()
    world.accept()
    world.verify_bol(who=world.exporter)
    assert world.state()["bol_verified"]


def test_stranger_cannot_submit_bol(world):
    world.open()
    world.accept()
    world.as_(world.stranger)
    assert_reverts("ERR_UNAUTHORIZED_PARTY", world.contract.verify_bill_of_lading, "LC-1", BOL, world.sign_bol())


def test_bol_can_only_be_verified_once(world):
    world.open()
    world.accept()
    world.verify_bol()
    world.as_(world.importer)
    assert_reverts("ERR_INVALID_STATE", world.contract.verify_bill_of_lading, "LC-1", BOL, world.sign_bol())


def _snapshot(world):
    return (world.state(), world.contract.get_protocol_summary())


def test_forged_signature_reverts_with_dedicated_error(world):
    world.open()
    world.accept()
    world.as_(world.importer)
    assert_reverts("ERR_INVALID_BOL_ATTESTATION", world.contract.verify_bill_of_lading, "LC-1", BOL, "00" * 64)


def test_forged_signature_mutates_nothing(world):
    world.open()
    world.accept()
    before = _snapshot(world)
    world.as_(world.importer)
    assert_reverts("ERR_INVALID_BOL_ATTESTATION", world.contract.verify_bill_of_lading, "LC-1", BOL, "11" * 64)
    assert _snapshot(world) == before


def test_forged_signature_performs_no_http_fetch(world):
    world.open()
    world.accept()
    world.vm.clear_mocks()
    world.as_(world.importer)
    assert_reverts("ERR_INVALID_BOL_ATTESTATION", world.contract.verify_bill_of_lading, "LC-1", BOL, "22" * 64)
    assert not world.vm._web_mocks_hit
    assert world.vm._captured_validators == []


@pytest.mark.parametrize(
    "sig",
    [
        "",
        "00",
        "00" * 63,
        "00" * 65,
        "zz" * 64,
        "AB" * 64,
        "0x" + "00" * 62,
        " " * 128,
    ],
)
def test_malformed_signature_strings_rejected(world, sig):
    world.open()
    world.accept()
    world.as_(world.importer)
    assert_reverts("ERR_INVALID_BOL_ATTESTATION", world.contract.verify_bill_of_lading, "LC-1", BOL, sig)


@pytest.mark.parametrize("idx", [0, 1, 7, 15, 31, 32, 33, 40, 47, 63])
def test_single_bit_flip_in_signature_rejected(world, idx):
    world.open()
    world.accept()
    sig = bytearray(bytes.fromhex(world.sign_bol()))
    sig[idx] ^= 0x80
    world.as_(world.importer)
    assert_reverts("ERR_INVALID_BOL_ATTESTATION", world.contract.verify_bill_of_lading, "LC-1", BOL, bytes(sig).hex())


def test_signature_from_a_different_authority_is_rejected(world):
    world.open()
    world.accept()
    impostor = Carrier(b"impostor-authority-seed-00000001")
    forged = impostor.sign(world.bol_message())
    world.as_(world.importer)
    assert_reverts("ERR_INVALID_BOL_ATTESTATION", world.contract.verify_bill_of_lading, "LC-1", BOL, forged)
    assert world.contract.check_bol_attestation("LC-1", BOL, forged) is False


def test_signature_over_a_different_bol_id_is_rejected(world):
    world.open()
    world.accept()
    sig = world.carrier.sign(world.contract.get_bol_message("LC-1", "BOL-OTHER"))
    world.as_(world.importer)
    assert_reverts("ERR_INVALID_BOL_ATTESTATION", world.contract.verify_bill_of_lading, "LC-1", BOL, sig)


FIELDS = ["bol", "lc", "container", "imo", "exporter", "cargo", "temp", "latest"]


@pytest.mark.parametrize("field", FIELDS)
def test_signature_over_any_altered_field_is_rejected(world, field):
    """The carrier signs eight fields; changing any one of them breaks it."""
    world.open()
    world.accept()
    parts = world.bol_message().split("|")
    idx = FIELDS.index(field)
    parts[idx] = parts[idx] + "x" if field in ("bol", "lc", "container") else {
        "imo": "9321483",
        "exporter": hex_of(world.stranger),
        "cargo": hashlib.sha256(b"different cargo").hexdigest(),
        "temp": str(MAX_TEMP + 1),
        "latest": str(LATEST + 1),
    }[field]
    forged = world.carrier.sign("|".join(parts))
    world.as_(world.importer)
    assert_reverts("ERR_INVALID_BOL_ATTESTATION", world.contract.verify_bill_of_lading, "LC-1", BOL, forged)


@pytest.mark.parametrize("field", ["container", "imo", "cargo", "temp", "latest"])
def test_lc_terms_are_what_the_signature_binds(world, field):
    """Opening an L/C with terms that differ from what the carrier signed makes the
    carrier's signature useless: the contract rebuilds the message from L/C terms."""
    world.open()
    signed_terms = world.bol_message().split("|")
    # a second L/C with one differing term cannot reuse a signature made for LC-1
    overrides = {
        "container": dict(container_id="MSKU7654321"),
        "imo": dict(vessel_imo="9321483"),
        "cargo": dict(cargo_spec_hash=hashlib.sha256(b"x").hexdigest()),
        "temp": dict(max_temp_tenths_c=MAX_TEMP + 10),
        "latest": dict(latest_arrival_ts=LATEST + 99),
    }
    world.open(**overrides[field])
    world.as_(world.exporter)
    world.contract.accept_lc_terms("LC-2")
    sig_for_lc1 = world.carrier.sign("|".join(signed_terms))
    world.as_(world.importer)
    assert_reverts("ERR_INVALID_BOL_ATTESTATION", world.contract.verify_bill_of_lading, "LC-2", BOL, sig_for_lc1)


def test_signature_for_another_lc_cannot_be_replayed(world):
    world.open()
    world.open()
    world.accept("LC-1")
    world.as_(world.exporter)
    world.contract.accept_lc_terms("LC-2")
    sig1 = world.sign_bol("LC-1")
    world.as_(world.importer)
    assert_reverts("ERR_INVALID_BOL_ATTESTATION", world.contract.verify_bill_of_lading, "LC-2", BOL, sig1)


def test_same_bol_id_cannot_back_two_letters_of_credit(world):
    world.open()
    world.open()
    world.accept("LC-1")
    world.as_(world.exporter)
    world.contract.accept_lc_terms("LC-2")
    world.verify_bol("LC-1")
    world.as_(world.importer)
    assert_reverts(
        "ERR_BOL_REPLAY", world.contract.verify_bill_of_lading, "LC-2", BOL, world.sign_bol("LC-2")
    )
    assert world.state("LC-2")["bol_verified"] is False


def test_distinct_bol_ids_back_distinct_letters(world):
    world.open()
    world.open()
    world.accept("LC-1")
    world.as_(world.exporter)
    world.contract.accept_lc_terms("LC-2")
    world.verify_bol("LC-1", "BOL-A")
    world.verify_bol("LC-2", "BOL-B")
    assert world.state("LC-1")["bol_record_id"] == "BOL-A"
    assert world.state("LC-2")["bol_record_id"] == "BOL-B"


@pytest.mark.parametrize("bad", ["", "A|B", "x" * 65, "has space", "tab\t", "unié", "semi;colon"])
def test_malformed_bol_record_ids_rejected(world, bad):
    world.open()
    world.accept()
    world.as_(world.importer)
    assert_reverts(
        "ERR_INVALID_BOL_ATTESTATION", world.contract.verify_bill_of_lading, "LC-1", bad, "00" * 64
    )


def test_pipe_injection_cannot_shift_field_boundaries(world):
    """A BoL id containing '|' would let one signed message parse two ways."""
    world.open()
    world.accept()
    world.as_(world.importer)
    assert_reverts(
        "ERR_INVALID_BOL_ATTESTATION",
        world.contract.verify_bill_of_lading,
        "LC-1",
        "BOL|LC-1|" + CONTAINER,
        "00" * 64,
    )


def test_unknown_lc_rejected(world):
    world.as_(world.importer)
    assert_reverts("ERR_UNKNOWN_LC", world.contract.verify_bill_of_lading, "LC-9", BOL, "00" * 64)


def test_settlement_is_blocked_until_bol_is_verified(world):
    world.open()
    world.accept()
    world.as_(world.importer)
    assert_reverts("ERR_BOL_NOT_VERIFIED", world.contract.settle_shipment_stage, "LC-1", 1)


def test_forged_bol_blocks_settlement_for_good(world):
    world.open()
    world.accept()
    world.as_(world.importer)
    assert_reverts("ERR_INVALID_BOL_ATTESTATION", world.contract.verify_bill_of_lading, "LC-1", BOL, "ab" * 64)
    assert_reverts("ERR_BOL_NOT_VERIFIED", world.contract.settle_shipment_stage, "LC-1", 1)


def test_ed25519_verification_is_deterministic_and_pure(world):
    world.open()
    sig = world.sign_bol()
    results = {world.contract.check_bol_attestation("LC-1", BOL, sig) for _ in range(5)}
    assert results == {True}


def test_pubkey_is_immutable_and_exposed(world, carrier):
    assert world.contract.get_protocol_summary()["carrier_authority_pubkey"] == carrier.pub_hex
    assert not hasattr(world.contract, "set_carrier_authority")
    assert not hasattr(world.contract, "rotate_carrier_authority")


def test_signature_with_trailing_data_is_rejected(world):
    world.open()
    world.accept()
    world.as_(world.importer)
    assert_reverts(
        "ERR_INVALID_BOL_ATTESTATION",
        world.contract.verify_bill_of_lading,
        "LC-1",
        BOL,
        world.sign_bol() + "00",
    )


def test_uppercase_signature_hex_is_rejected(world):
    world.open()
    world.accept()
    world.as_(world.importer)
    assert_reverts(
        "ERR_INVALID_BOL_ATTESTATION",
        world.contract.verify_bill_of_lading,
        "LC-1",
        BOL,
        world.sign_bol().upper(),
    )
