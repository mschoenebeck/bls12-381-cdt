// P2B verification-only Antelope CDT/WASM contract.
// DO NOT deploy to a production account. Use a disposable BLS-enabled testnet.
// Action arguments: the 9 hex-encoded byte vectors produced by
// python3 tests/test_p2b_real_vectors.py --output /tmp/p2b-real-vectors.json
#include <eosio/eosio.hpp>
#include <array>
#include <vector>
#include <algorithm>
#include <span>
#include "../bls12-381-cdt.hpp"

using namespace eosio;
using namespace bls12_381;

CONTRACT p2bprobe : public contract {
public:
    using contract::contract;
    ACTION qualify(const std::vector<uint8_t>& pk_a,
                   const std::vector<uint8_t>& pk_b,
                   const std::vector<uint8_t>& message_a,
                   const std::vector<uint8_t>& message_b,
                   const std::vector<uint8_t>& signature_a,
                   const std::vector<uint8_t>& signature_b,
                   const std::vector<uint8_t>& aggregate_signature,
                   const std::vector<uint8_t>& expected_hash_a,
                   const std::vector<uint8_t>& expected_hash_b)
    {
        auto view = [](const std::vector<uint8_t>& v) {
            return std::span<const uint8_t>(v.data(), v.size());
        };
        auto key_a = validated_g1_affine_le::fromAffineBytesLE(view(pk_a));
        auto key_b = validated_g1_affine_le::fromAffineBytesLE(view(pk_b));
        auto sig_a = validated_g2_affine_le::fromAffineBytesLE(view(signature_a));
        auto sig_b = validated_g2_affine_le::fromAffineBytesLE(view(signature_b));
        auto sig_agg = validated_g2_affine_le::fromAffineBytesLE(view(aggregate_signature));
        check(key_a.has_value() && key_b.has_value() && sig_a.has_value() &&
              sig_b.has_value() && sig_agg.has_value(), "P2B: real affine input validation failed");

        auto hashed_a = hash_to_g2(view(message_a), signature_suite::basic);
        auto hashed_b = hash_to_g2(view(message_b), signature_suite::basic);
        check(hashed_a.has_value() && hashed_b.has_value(), "P2B: real hash_to_g2 failed");
        auto raw_a = hashed_a.value().point().toAffineBytesLE();
        auto raw_b = hashed_b.value().point().toAffineBytesLE();
        check(raw_a.size() == expected_hash_a.size() &&
              std::equal(raw_a.begin(), raw_a.end(), expected_hash_a.begin()),
              "P2B: real hash_to_g2 A mismatch with independent reference");
        check(raw_b.size() == expected_hash_b.size() &&
              std::equal(raw_b.begin(), raw_b.end(), expected_hash_b.begin()),
              "P2B: real hash_to_g2 B mismatch with independent reference");

        auto expect_verdict = [](const result<signature_verdict>& verdict,
                                 signature_verdict expected, const char* reason) {
            check(verdict.has_value() && verdict.value() == expected, reason);
        };
        expect_verdict(verify_basic_g2_signature(key_a.value(), view(message_a), sig_a.value()),
                       signature_verdict::valid, "P2B: valid individual A rejected");
        expect_verdict(verify_basic_g2_signature(key_b.value(), view(message_b), sig_b.value()),
                       signature_verdict::valid, "P2B: valid individual B rejected");
        std::vector<uint8_t> altered_message = message_a;
        altered_message.push_back('!');
        expect_verdict(verify_basic_g2_signature(key_a.value(), view(altered_message), sig_a.value()),
                       signature_verdict::invalid, "P2B: changed message accepted");
        expect_verdict(verify_basic_g2_signature(key_b.value(), view(message_a), sig_a.value()),
                       signature_verdict::invalid, "P2B: wrong key accepted");
        expect_verdict(verify_basic_g2_signature(key_a.value(), view(message_a), sig_b.value()),
                       signature_verdict::invalid, "P2B: different valid signature accepted");

        auto corrupt_signature = signature_a;
        corrupt_signature.back() ^= 1;
        auto corrupt = validated_g2_affine_le::fromAffineBytesLE(view(corrupt_signature));
        if(corrupt.has_value()) {
            auto negative = verify_basic_g2_signature(key_a.value(), view(message_a), corrupt.value());
            check(!negative.has_value() || negative.value() == signature_verdict::invalid,
                  "P2B: modified signature accepted");
        }

        std::array<validated_g1_affine_le, 2> keys{key_a.value(), key_b.value()};
        std::array<binary_message_view, 2> messages{view(message_a), view(message_b)};
        expect_verdict(aggregate_verify_basic(keys, messages, sig_agg.value()),
                       signature_verdict::valid, "P2B: valid distinct-message aggregate rejected");
        std::array<binary_message_view, 2> swapped{view(message_b), view(message_a)};
        expect_verdict(aggregate_verify_basic(keys, swapped, sig_agg.value()),
                       signature_verdict::invalid, "P2B: swapped-message aggregate accepted");
        print("P2B_REAL_CDT_WASM_PASS");
    }
};

EOSIO_DISPATCH(p2bprobe, (qualify))
