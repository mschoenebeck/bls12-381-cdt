# bls12-381-cdt

**Header-only BLS12-381 and Groth16 utilities for Antelope smart contracts.**

`bls12-381-cdt` provides compact C++ wrappers and higher-level helpers around the native BLS12-381 host functions exposed by Antelope Leap and CDT. Expensive curve and pairing operations execute through the chain's native intrinsics rather than a full curve implementation compiled into the smart contract.

The library was built for the cryptographic smart-contract layer of the CLOAK / ZEOS Caterpillar Shielded Protocol.

## What It Provides

- scalar-field and base-field value types;
- `Fp2`, `Fp6`, and `Fp12` extension-field wrappers;
- G1 and G2 point arithmetic;
- G1/G2 weighted sums and multi-scalar multiplication;
- BLS12-381 pairing evaluation;
- field-to-curve mapping;
- XMD-SHA-256 based message-to-G2 support;
- Groth16 proof, verifying-key, and prepared-key types;
- Groth16 proof verification;
- Jubjub helpers used by the shielded protocol;
- little-endian affine serialization helpers for contract-side data exchange.

## Architecture

```text
High-level contract helpers
        │
        ├── Groth16 verification
        ├── BLS / pairing operations
        ├── message-to-G2
        └── Jubjub helpers
        │
Antelope CDT BLS interfaces
        │
Leap BLS12-381 host functions
        │
Native high-performance implementation
```

This repository is not a second full BLS12-381 implementation compiled to WASM. It is the smart-contract-facing layer above the native primitives.

Related work:

- [`mschoenebeck/bls12-381`](https://github.com/mschoenebeck/bls12-381) — native C++/x86-64 BLS12-381 implementation;
- [Antelope Leap PR #1071](https://github.com/AntelopeIO/leap/pull/1071) — BLS12-381 host functions;
- [Antelope CDT PR #154](https://github.com/AntelopeIO/cdt/pull/154) — CDT smart-contract interfaces for those primitives;
- [`mschoenebeck/zeos-caterpillar`](https://github.com/mschoenebeck/zeos-caterpillar) — shielded-protocol cryptographic engine.

## Requirements

The consuming contract must be built with an Antelope CDT version that provides:

```cpp
#include <eosio/crypto_bls_ext.hpp>
```

The target chain must expose the corresponding BLS12-381 host functions and have the required BLS protocol feature activated.

The header uses C++20 `std::span` and is intended for Antelope smart-contract builds.

## Usage

Copy or include `bls12-381-cdt.hpp` in the consuming contract:

```cpp
#include "bls12-381-cdt.hpp"

using namespace bls12_381;
```

Example primitive operations:

```cpp
g1 p = g1::one();
g1 q = p.mulScalar(scalar(1, 0, 0, 0));
g1 r = p.add(q);
```

Example Groth16 verification:

```cpp
std::vector<scalar> public_inputs = {
    scalar(1, 0, 0, 0), // required leading Groth16 constant
    input_0,
    input_1
};

bool valid = groth16::verify_proof(prepared_vk, proof, public_inputs);
```

For serialized verifying keys held in a vector, prefer the bounded overload:

```cpp
groth16::VerifyingKey vk =
    groth16::VerifyingKey::fromAffineBytesLE(vk_bytes);
```

### Groth16 public-input convention

`verify_proof()` expects exactly one scalar for every entry in `PreparedVerifyingKey::ic`.

The function does **not** insert the conventional implicit constant internally. The caller must therefore provide:

```text
[ 1, public_input_0, public_input_1, ... ]
```

where the first element is the canonical non-Montgomery scalar one, `scalar(1, 0, 0, 0)`.

This convention is intentional and matches the current CLOAK Shielded Protocol contract integration.

## SHA-256 and Message-to-G2

The XMD expansion used by `fromMessage()` delegates SHA-256 hashing to Antelope's native `eosio::sha256()` host function. No standalone SHA-256 implementation is bundled with this repository.

The XMD byte construction remains explicit in the header so its domain-separation and expansion behavior can be inspected.

## Serialization and Layout

The library uses fixed-size field and point representations that map directly onto the CDT BLS types. Compile-time size assertions guard the layout assumptions used by those conversions.

Affine byte parsers are explicitly little-endian. This matches the WASM execution environment and the serialization used by the current shielded-protocol integration.

For the Groth16 public-input vector, the canonical scalar value one is `scalar(1, 0, 0, 0)`. `scalar::one()` represents the Montgomery-domain value used by the library's internal scalar-field arithmetic and is not the leading Groth16 input used by the current contract integration.

### Strict canonical Fr input

For untrusted **32-byte little-endian raw Fr values**, use `scalar::tryFromCanonicalBytesLE(bytes)` (fixed-size `std::span` or `std::vector` overload). It returns `std::nullopt` unless the input is exactly 32 bytes and its unsigned integer value is strictly below `scalar::Q`; it never silently reduces modulo the field modulus. Use `value.isCanonicalRaw()` when the scalar is already known to represent a **raw, non-Montgomery** field encoding. These helpers do not validate other scalar domains or change the permissive legacy `scalar::fromBytesLE()` APIs.

The standalone host boundary regression is `python3 tests/test_scalar_canonical.py` (requires Python 3.7+ and a C++20 compiler). It compiles the new production method bodies, extracted from this header, against a minimal test representation and compares their behavior to an independent Python big-integer oracle. It is **not** a substitute for compiling the complete header with Antelope CDT and running contract integration tests.

For verifying keys stored in `std::vector<uint8_t>`, use the vector overloads of `fromAffineBytesLE()`. They validate the fixed prefix and embedded IC-vector length before delegating to the compatibility-preserving raw-pointer parser. The raw-pointer overloads remain available for existing callers and assume that the caller has already validated the buffer length.

## Status and Security

This code is used by the CLOAK / ZEOS Caterpillar smart-contract stack, but this repository does not claim an independent standalone security audit.

Cryptographic callers are responsible for:

- validating serialized input lengths before raw-pointer parsing;
- using the expected domain-separation tag;
- supplying Groth16 public inputs in the documented order;
- deploying only to chains with compatible BLS host functions;
- validating their own proofs, keys, and integration assumptions.

## Checked BLS Signature Boundary

The header exposes the authoritative Basic G2-signature ciphersuite domain-separation tag used by the pinned Antelope BLS implementation:

```cpp
bls12_381::ciphersuites::basic_signature_g2
```

For signature verification, use the checked boundary types rather than importing untrusted bytes directly into raw `g1` or `g2` values:

```cpp
auto public_key = validated_g1_affine_le::fromAffineBytesLE(public_key_bytes);
auto signature = validated_g2_affine_le::fromAffineBytesLE(signature_bytes);

eosio::check(public_key.has_value(), "invalid BLS public key");
eosio::check(signature.has_value(), "invalid BLS signature");

auto verdict = verify_basic_g2_signature(
    public_key.value(),
    std::span<const uint8_t>(message.data(), message.size()),
    signature.value()
);

eosio::check(verdict.has_value(), "BLS verification operation failed");
eosio::check(verdict.value() == signature_verdict::valid, "invalid BLS signature");
```

The checked G1/G2 factories require the exact affine little-endian size and reject noncanonical or off-curve input, points outside the prime-order subgroup, and the identity point.

Public keys can be aggregated after validation:

```cpp
auto aggregate_key = aggregate_public_keys(validated_keys);
```

Basic aggregate verification accepts one or more **distinct-message groups**:

```cpp
auto verdict = aggregate_verify_basic(
    grouped_public_keys,
    messages,
    aggregate_signature
);
```

The function rejects empty input, mismatched key/message counts, duplicate messages, malformed or non-subgroup points, identity points, and host-operation failures. An ordinary pairing mismatch is returned as `signature_verdict::invalid` rather than as an operational error.

`hash_to_g2(message, dst)` remains available as the generic low-level binary message-to-curve operation. Named Basic verification functions bind the Basic ciphersuite internally so callers cannot accidentally select another DST.

### Compatibility boundary

The new subgroup and identity checks apply only when constructing `validated_g1_affine_le` and `validated_g2_affine_le`, and therefore only to the new signature-facing API.

Existing raw arithmetic, raw affine constructors, and Groth16 verification do **not** gain automatic subgroup or identity checks. Their existing successful behavior and serialized layouts are preserved. Existing host-backed operations now inspect the status returned by the native intrinsic and fail closed instead of consuming an output after host failure.

Protocol-level rules remain the consuming contract's responsibility, including key authorization, policy ordering, duplicate-key policy, thresholds, vote bitsets, and message construction outside the generic BLS scheme.

## License

MIT License. See [`LICENSE`](LICENSE).

## Author

**Matthias Schönebeck**

Blockchain, DeFi, and applied-cryptography infrastructure engineer.

- [GitHub](https://github.com/mschoenebeck)
- [X / Twitter](https://x.com/mschoenebeck1)
- [CLOAK](https://cloak.today)
- [Email](mailto:matthias.schoenebeck@gmail.com)
