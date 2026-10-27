#!/usr/bin/env python3
"""P2B real BLS vectors, independent py_ecc G2Basic reference backend.

Requires: pip install 'py_ecc>=8,<9' (verify/pin version in qualification report).
Usage: python3 tests/test_p2b_real_vectors.py --output /tmp/p2b-real-vectors.json

The emitted action_data is suitable for the *test-only* p2b_real_contract.cpp
CDT/WASM contract's ``qualify`` action on a non-production Antelope chain.
Passing this Python reference suite alone DOES NOT validate the CDT host path.
Actual chain execution with the generated vectors must also pass.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

DST = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_"


def reference_vectors() -> dict:
    try:
        from py_ecc.bls import G2Basic
        from py_ecc.bls.hash_to_curve import hash_to_G2
        from py_ecc.bls.point_compression import decompress_G1, decompress_G2
        from py_ecc.optimized_bls12_381 import field_modulus, normalize
        from importlib.metadata import version
    except ImportError as exc:
        raise SystemExit(
            "P2B REAL KAT NOT RUN: install independent backend: "
            "python3 -m pip install 'py_ecc>=8,<9'"
        ) from exc

    # Native Antelope CDT affine coordinates use six little-endian 64-bit
    # Montgomery limbs for each Fp component. This conversion is part of
    # the integration hypothesis checked by the ACTUAL CDT/WASM probe.
    montgomery_r = (1 << 384) % field_modulus

    def fp_le_montgomery(value: int) -> bytes:
        return (int(value) * montgomery_r % field_modulus).to_bytes(48, "little")

    def g1_host(point) -> bytes:
        x, y = normalize(point)
        return fp_le_montgomery(x.n) + fp_le_montgomery(y.n)

    def g2_host(point) -> bytes:
        x, y = normalize(point)
        return b"".join(fp_le_montgomery(z) for z in (*x.coeffs, *y.coeffs))

    def decompressed_pk(pk: bytes):
        return decompress_G1(int.from_bytes(pk, "big"))

    def decompressed_sig(sig: bytes):
        return decompress_G2((int.from_bytes(sig[:48], "big"), int.from_bytes(sig[48:], "big")))

    # Fixed deterministic keys and messages: reproducible Basic G2 KATs.
    secrets = (23, 37)
    messages = (b"p2b-basic-a", b"p2b-basic-b")
    pks = [G2Basic.SkToPk(x) for x in secrets]
    sigs = [G2Basic.Sign(sk, msg) for sk, msg in zip(secrets, messages)]
    agg = G2Basic.Aggregate(sigs)
    assert len(pks[0]) == len(pks[1]) == 48
    assert len(sigs[0]) == len(sigs[1]) == len(agg) == 96
    assert all(G2Basic.Verify(pk, msg, sig) for pk, msg, sig in zip(pks, messages, sigs))
    assert not G2Basic.Verify(pks[0], messages[0] + b"!", sigs[0])
    assert not G2Basic.Verify(pks[1], messages[0], sigs[0])
    assert not G2Basic.Verify(pks[0], messages[0], sigs[1])
    bad = bytearray(sigs[0])
    bad[-1] ^= 1
    assert not G2Basic.Verify(pks[0], messages[0], bytes(bad))
    assert G2Basic.AggregateVerify(pks, messages, agg)
    assert not G2Basic.AggregateVerify(pks, list(reversed(messages)), agg)

    hash_a = g2_host(hash_to_G2(messages[0], DST, hashlib.sha256))
    hash_b = g2_host(hash_to_G2(messages[1], DST, hashlib.sha256))
    assert hash_a != hash_b
    host_pk = [g1_host(decompressed_pk(v)) for v in pks]
    host_sig = [g2_host(decompressed_sig(v)) for v in sigs]
    host_agg = g2_host(decompressed_sig(agg))
    assert all(len(x) == 96 for x in host_pk)
    assert all(len(x) == 192 for x in (*host_sig, host_agg, hash_a, hash_b))

    names = [
        "pk_a", "pk_b", "message_a", "message_b", "signature_a",
        "signature_b", "aggregate_signature", "expected_hash_a", "expected_hash_b",
    ]
    values = [*host_pk, *messages, *host_sig, host_agg, hash_a, hash_b]
    payload = {k: v.hex() for k, v in zip(names, values)}
    return {
        "scheme": "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_",
        "reference_backend": f"py_ecc {version('py-ecc')} G2Basic",
        "keys": list(secrets),
        "checks": ["individual_positive", "altered_message_negative", "wrong_key_negative",
                   "other_valid_signature_negative", "tampered_signature_negative",
                   "distinct_message_aggregate_positive", "swapped_message_aggregate_negative",
                   "independent_hash_to_G2"],
        "action_data": payload,
        "action_arguments_in_order": [payload[n] for n in names],
    }


def main() -> None:
    if not __debug__:
        raise SystemExit("P2B requires Python assertions enabled (do not use -O)")
    ap = argparse.ArgumentParser()
    ap.add_argument("--output", type=Path, required=True,
                    help="Write independent reference vectors and real CDT action arguments")
    args = ap.parse_args()
    vectors = reference_vectors()  # Missing backend or any failed KAT is a hard error.
    args.output.write_text(json.dumps(vectors, indent=2) + "\n", encoding="utf-8")
    print(f"PASS P2B REAL REFERENCE ONLY: {vectors['reference_backend']}; "
          f"{len(vectors['checks'])} cryptographic reference checks")
    print(f"VECTORS: {args.output}")
    print("NOT YET QUALIFIED: deploy and execute tests/p2b_real_contract.cpp "
          "with action_arguments_in_order on a non-production CDT/BLS-enabled chain.")


if __name__ == "__main__":
    main()
