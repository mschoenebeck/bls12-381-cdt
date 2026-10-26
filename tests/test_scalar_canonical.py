#!/usr/bin/env python3
"""Host oracle for the *production* scalar canonical-decoding method bodies.

The standalone header needs Antelope CDT. To keep these security boundary tests
runnable with ordinary C++20, extract the exact three production method bodies
and the actual Q initializer into a minimal scalar test harness. This is not
an Antelope/WASM compilation or integration test.

Usage: python3 tests/test_scalar_canonical.py
"""

from __future__ import annotations

import os
from pathlib import Path
import random
import re
import shutil
import subprocess
import tempfile

HEADER = Path(__file__).resolve().parents[1] / "bls12-381-cdt.hpp"
FR_Q = int("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001", 16)


def extract_method(header: str, signature: str) -> str:
    start = header.find(signature)
    if start < 0 or header.find(signature, start + 1) >= 0:
        raise AssertionError(f"Missing or ambiguous production method: {signature}")
    open_brace = header.find("{", start)
    if open_brace < 0:
        raise AssertionError(f"Method missing body: {signature}")
    depth = 0
    for index in range(open_brace, len(header)):
        if header[index] == "{":
            depth += 1
        elif header[index] == "}":
            depth -= 1
            if depth == 0:
                return header[start:index + 1]
    raise AssertionError(f"Method has unbalanced braces: {signature}")


def make_harness(header: str) -> str:
    signatures = [
        "bool isCanonicalRaw() const",
        "static std::optional<scalar> tryFromCanonicalBytesLE(\n            std::span<const uint8_t, 32> bytes)",
        "static std::optional<scalar> tryFromCanonicalBytesLE(\n            const std::vector<uint8_t>& bytes)",
    ]
    methods = "\n".join(extract_method(header, signature) for signature in signatures)
    qmatch = re.search(r"inline const scalar scalar::Q\s*=\s*\{[^{}]*\};", header)
    if not qmatch:
        raise AssertionError("Cannot locate production scalar::Q initializer")

    source = r'''
#include <array>
#include <cassert>
#include <cstdint>
#include <iostream>
#include <optional>
#include <span>
#include <string>
#include <vector>

struct scalar {
    uint64_t w0, w1, w2, w3;
    scalar() : w0(0), w1(0), w2(0), w3(0) {}
    scalar(uint64_t a, uint64_t b, uint64_t c, uint64_t d)
        : w0(a), w1(b), w2(c), w3(d) {}
    uint64_t& operator[](int index) {
        switch (index) {
            case 0: return w0;
            case 1: return w1;
            case 2: return w2;
            case 3: return w3;
        }
        std::abort();
    }
    static const scalar Q;
__METHODS__
};
__MODULUS__

int main() {
    const char* hexchars = "0123456789abcdef";
    std::string encoded;
    while (std::cin >> encoded) {
        if (encoded == "-") encoded.clear();
        assert(encoded.size() % 2 == 0);
        std::vector<uint8_t> bytes;
        bytes.reserve(encoded.size() / 2);
        for (std::size_t i = 0; i < encoded.size(); i += 2) {
            auto val = [](char c) -> uint8_t {
                if (c >= '0' && c <= '9') return static_cast<uint8_t>(c - '0');
                return static_cast<uint8_t>(c - 'a' + 10);
            };
            bytes.push_back(static_cast<uint8_t>((val(encoded[i]) << 4) | val(encoded[i + 1])));
        }
        auto parsed = scalar::tryFromCanonicalBytesLE(bytes);
        if (bytes.size() == 32) {
            const auto spanResult = scalar::tryFromCanonicalBytesLE(
                std::span<const uint8_t, 32>(bytes.data(), 32));
            assert(parsed.has_value() == spanResult.has_value());
            scalar raw;
            for (int i = 0; i < 4; ++i) {
                uint64_t limb = 0;
                for (int j = 0; j < 8; ++j)
                    limb |= static_cast<uint64_t>(bytes[i * 8 + j]) << (j * 8);
                raw[i] = limb;
            }
            assert(raw.isCanonicalRaw() == parsed.has_value());
        }
        if (!parsed) {
            std::cout << "invalid\n";
            continue;
        }
        std::cout << "valid ";
        for (int i = 0; i < 4; ++i) {
            for (int j = 0; j < 8; ++j) {
                const uint8_t b = static_cast<uint8_t>((*parsed)[i] >> (j * 8));
                std::cout << hexchars[b >> 4] << hexchars[b & 15];
            }
        }
        std::cout << '\n';
    }
}
'''
    return source.replace("__METHODS__", methods).replace("__MODULUS__", qmatch.group())


def exercise(binary: Path) -> int:
    rng = random.Random(0x381C0A1)
    values: list[bytes] = [
        b"", bytes(31), bytes(33), bytes(64),
        *(n.to_bytes(32, "little") for n in (
            0, 1, 2, FR_Q - 2, FR_Q - 1, FR_Q, FR_Q + 1,
            2 * FR_Q - 1, 2 * FR_Q, 2 * FR_Q + 1, 2**255, 2**256 - 1,
            1 << 64, 1 << 192, 1 << 248,
        )),
    ]
    for _ in range(2000):
        values.append(rng.getrandbits(256).to_bytes(32, "little"))
    for size in (1, 2, 8, 16, 30, 31, 33, 34, 48, 63):
        values.extend(rng.getrandbits(size * 8).to_bytes(size, "little") for _ in range(8))
    encoded = "\n".join(v.hex() if v else "-" for v in values) + "\n"
    outcome = subprocess.run([str(binary)], input=encoded, text=True,
                             capture_output=True, check=True)
    got = outcome.stdout.splitlines()
    assert len(got) == len(values), (len(got), len(values), outcome.stderr)
    for index, (sample, actual) in enumerate(zip(values, got)):
        is_valid = len(sample) == 32 and int.from_bytes(sample, "little") < FR_Q
        expected = f"valid {sample.hex()}" if is_valid else "invalid"
        if actual != expected:
            raise AssertionError(
                f"Mismatch sample {index}: input={sample.hex()} expected={expected} actual={actual}"
            )
    return len(values)


def main() -> None:
    compiler = os.environ.get("CXX", "g++")
    if shutil.which(compiler) is None:
        raise SystemExit(f"C++20 compiler not found: {compiler}")
    header = HEADER.read_text(encoding="utf-8")
    with tempfile.TemporaryDirectory(prefix="bls-scalar-canonical-") as directory:
        source = Path(directory) / "test.cpp"
        binary = Path(directory) / "test"
        source.write_text(make_harness(header), encoding="utf-8")
        subprocess.run([compiler, "-std=c++20", "-O2", "-Wall", "-Wextra", "-Werror",
                        str(source), "-o", str(binary)], check=True)
        count = exercise(binary)
    print(f"BLS12-381 canonical Fr host oracle PASS ({count} inputs)")
    print("NOTE: host extraction test only; native Antelope CDT build remains required.")


if __name__ == "__main__":
    main()
