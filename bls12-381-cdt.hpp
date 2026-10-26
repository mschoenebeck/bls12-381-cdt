#pragma once

#include <eosio/eosio.hpp>
#include <eosio/crypto.hpp>
#include <eosio/crypto_bls_ext.hpp>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <limits>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#ifndef __eosio_cdt__
typedef __int128 int128_t;
typedef unsigned __int128 uint128_t;
#endif

namespace bls12_381_cdt_detail
{
    inline bool hasHexPrefix(const std::string& s)
    {
        return s.size() >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X');
    }

    inline int16_t hexNibble(const char c)
    {
        if(c >= '0' && c <= '9') return static_cast<int16_t>(c - '0');
        if(c >= 'a' && c <= 'f') return static_cast<int16_t>(c - 'a' + 10);
        if(c >= 'A' && c <= 'F') return static_cast<int16_t>(c - 'A' + 10);
        return -1;
    }

    inline std::array<uint8_t, 32> sha256Digest(const std::vector<uint8_t>& input)
    {
        eosio::check(input.size() <= std::numeric_limits<uint32_t>::max(), "SHA-256 input too large");
        const char* data = input.empty() ? "" : reinterpret_cast<const char*>(input.data());
        return eosio::sha256(data, static_cast<uint32_t>(input.size())).extract_as_byte_array();
    }

    inline uint32_t readUint32LE(const uint8_t* in)
    {
        return static_cast<uint32_t>(in[0]) |
               (static_cast<uint32_t>(in[1]) << 8) |
               (static_cast<uint32_t>(in[2]) << 16) |
               (static_cast<uint32_t>(in[3]) << 24);
    }

    inline size_t encodedVectorSize(const size_t prefix_size, const uint32_t count, const size_t element_size)
    {
        eosio::check(
            static_cast<size_t>(count) <= (std::numeric_limits<size_t>::max() - prefix_size) / element_size,
            "encoded vector size overflow"
        );
        return prefix_size + static_cast<size_t>(count) * element_size;
    }
}

template<size_t N>
inline std::string bytesToHex(const std::span<const uint8_t, N>& in)
{
    constexpr char hexmap[] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
    std::string s(N * 2, ' ');
    for(size_t i = 0; i < N; i++)
    {
        s[2*i]     = hexmap[(in[i] & 0xF0) >> 4];
        s[2*i+1]   = hexmap[ in[i] & 0x0F      ];
    }
    return s;
}

inline std::string bytesToHex(const std::vector<uint8_t>& in)
{
    constexpr char hexmap[] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
    std::string s(in.size() * 2, ' ');
    for(size_t i = 0; i < in.size(); ++i)
    {
        s[2*i]     = hexmap[(in[i] & 0xF0) >> 4];
        s[2*i+1]   = hexmap[ in[i] & 0x0F      ];
    }
    return s;
}

template<size_t N>
inline void hexToBytes(const std::string& s, std::span<uint8_t, N> out)
{
    const size_t start_idx = bls12_381_cdt_detail::hasHexPrefix(s) ? 2 : 0;
    eosio::check(s.size() >= start_idx + 2 * N, "hexToBytes: input is too short");

    for(size_t i = 0, j = start_idx; i < N; i++, j += 2)
    {
        const int16_t hi = bls12_381_cdt_detail::hexNibble(s[j]);
        const int16_t lo = bls12_381_cdt_detail::hexNibble(s[j+1]);
        eosio::check(hi >= 0 && lo >= 0, "hexToBytes: invalid hexadecimal character");
        out[i] = static_cast<uint8_t>((hi << 4) | lo);
    }
}

template<size_t N>
inline std::array<uint8_t, N> hexToBytes(const std::string& s)
{
    std::array<uint8_t, N> out{};
    hexToBytes<N>(s, out);
    return out;
}

inline std::vector<uint8_t> hexToBytes(const std::string& s)
{
    const size_t start_idx = bls12_381_cdt_detail::hasHexPrefix(s) ? 2 : 0;
    const size_t hex_length = s.size() - start_idx;
    if(hex_length % 2 != 0)
    {
        return {};
    }

    std::vector<uint8_t> bytes;
    const size_t num_bytes = hex_length / 2;
    bytes.reserve(num_bytes);
    for(size_t i = 0, j = start_idx; i < num_bytes; i++, j += 2)
    {
        const int16_t hi = bls12_381_cdt_detail::hexNibble(s[j]);
        const int16_t lo = bls12_381_cdt_detail::hexNibble(s[j+1]);
        if(hi < 0 || lo < 0)
        {
            return {};
        }
        bytes.push_back(static_cast<uint8_t>((hi << 4) | lo));
    }

    return bytes;
}

inline std::vector<std::string> split(std::string str, char separator)
{
    std::vector<std::string> strings;
    size_t start = 0;
    for(size_t i = 0; i <= str.size(); i++)
    {
        // Check the boundary before indexing str[i].
        if(i == str.size() || str[i] == separator)
        {
            strings.emplace_back(str.substr(start, i - start));
            start = i + 1;
        }
    }
    return strings;
}

namespace bls12_381
{
    namespace sizes
    {
        inline constexpr size_t scalar_bytes       = 32;
        inline constexpr size_t fp_bytes           = 48;
        inline constexpr size_t fp2_bytes          = 96;
        inline constexpr size_t g1_affine_le_bytes = 96;
        inline constexpr size_t g2_affine_le_bytes = 192;
        inline constexpr size_t gt_bytes           = 576;
    }

    namespace ciphersuites
    {
        inline constexpr std::string_view basic_signature_g2 =
            "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";
    }

    enum class signature_suite : uint8_t
    {
        basic
    };

    inline constexpr std::string_view ciphersuite_dst(const signature_suite)
    {
        return ciphersuites::basic_signature_g2;
    }

    enum class bls_errc : uint8_t
    {
        none,
        empty_input,
        invalid_length,
        length_mismatch,
        count_overflow,
        malformed_g1,
        malformed_g2,
        identity_point,
        wrong_subgroup,
        duplicate_message,
        host_operation_failed,
        unsupported_environment
    };

    struct bls_error
    {
        bls_errc code = bls_errc::none;
        int32_t host_status = 0;
    };

    enum class signature_verdict : uint8_t
    {
        invalid,
        valid
    };

    template<class T>
    class result
    {
        public:
        static result success(T value)
        {
            return result(std::move(value));
        }

        static result failure(const bls_errc code, const int32_t host_status = 0)
        {
            return result(bls_error{code, host_status});
        }

        bool has_value() const
        {
            return value_.has_value();
        }

        explicit operator bool() const
        {
            return has_value();
        }

        const T& value() const
        {
            eosio::check(has_value(), "bls12-381-cdt: attempted to access a failed result");
            return *value_;
        }

        T& value()
        {
            eosio::check(has_value(), "bls12-381-cdt: attempted to access a failed result");
            return *value_;
        }

        T take_value()
        {
            eosio::check(has_value(), "bls12-381-cdt: attempted to access a failed result");
            T out = std::move(*value_);
            value_.reset();
            return out;
        }

        const bls_error& error() const
        {
            return error_;
        }

        private:
        explicit result(T value) : value_(std::move(value)), error_{} {}
        explicit result(const bls_error error) : value_(std::nullopt), error_(error) {}

        std::optional<T> value_;
        bls_error error_;
    };

    namespace host_detail
    {
        template<class T>
        inline result<T> host_failure(const int32_t status)
        {
            return result<T>::failure(bls_errc::host_operation_failed, status);
        }

        inline bool valid_count_for_host(const size_t count, const size_t element_size)
        {
            return count > 0 &&
                   count <= std::numeric_limits<uint32_t>::max() &&
                   count <= std::numeric_limits<uint32_t>::max() / element_size;
        }

        inline result<eosio::bls_g1> g1_add(const eosio::bls_g1& lhs, const eosio::bls_g1& rhs)
        {
            eosio::bls_g1 out{};
            const int32_t status = eosio::bls_g1_add(lhs, rhs, out);
            if(status != 0) return host_failure<eosio::bls_g1>(status);
            return result<eosio::bls_g1>::success(out);
        }

        inline result<eosio::bls_g2> g2_add(const eosio::bls_g2& lhs, const eosio::bls_g2& rhs)
        {
            eosio::bls_g2 out{};
            const int32_t status = eosio::bls_g2_add(lhs, rhs, out);
            if(status != 0) return host_failure<eosio::bls_g2>(status);
            return result<eosio::bls_g2>::success(out);
        }

        inline result<eosio::bls_g1> g1_weighted_sum(
            const eosio::bls_g1 points[],
            const eosio::bls_scalar scalars[],
            const size_t count
        )
        {
            if(!valid_count_for_host(count, sizeof(eosio::bls_g1)) ||
               !valid_count_for_host(count, sizeof(eosio::bls_scalar)))
            {
                return result<eosio::bls_g1>::failure(count == 0 ? bls_errc::empty_input : bls_errc::count_overflow);
            }
            eosio::bls_g1 out{};
            const int32_t status = eosio::bls_g1_weighted_sum(points, scalars, static_cast<uint32_t>(count), out);
            if(status != 0) return host_failure<eosio::bls_g1>(status);
            return result<eosio::bls_g1>::success(out);
        }

        inline result<eosio::bls_g2> g2_weighted_sum(
            const eosio::bls_g2 points[],
            const eosio::bls_scalar scalars[],
            const size_t count
        )
        {
            if(!valid_count_for_host(count, sizeof(eosio::bls_g2)) ||
               !valid_count_for_host(count, sizeof(eosio::bls_scalar)))
            {
                return result<eosio::bls_g2>::failure(count == 0 ? bls_errc::empty_input : bls_errc::count_overflow);
            }
            eosio::bls_g2 out{};
            const int32_t status = eosio::bls_g2_weighted_sum(points, scalars, static_cast<uint32_t>(count), out);
            if(status != 0) return host_failure<eosio::bls_g2>(status);
            return result<eosio::bls_g2>::success(out);
        }

        inline result<eosio::bls_gt> pairing(
            const eosio::bls_g1 g1_points[],
            const eosio::bls_g2 g2_points[],
            const size_t count
        )
        {
            if(!valid_count_for_host(count, sizeof(eosio::bls_g1)) ||
               !valid_count_for_host(count, sizeof(eosio::bls_g2)))
            {
                return result<eosio::bls_gt>::failure(count == 0 ? bls_errc::empty_input : bls_errc::count_overflow);
            }
            eosio::bls_gt out{};
            const int32_t status = eosio::bls_pairing(g1_points, g2_points, static_cast<uint32_t>(count), out);
            if(status != 0) return host_failure<eosio::bls_gt>(status);
            return result<eosio::bls_gt>::success(out);
        }

        inline result<eosio::bls_g1> g1_map(const eosio::bls_fp& element)
        {
            eosio::bls_g1 out{};
            const int32_t status = eosio::bls_g1_map(element, out);
            if(status != 0) return host_failure<eosio::bls_g1>(status);
            return result<eosio::bls_g1>::success(out);
        }

        inline result<eosio::bls_g2> g2_map(const eosio::bls_fp2& element)
        {
            eosio::bls_g2 out{};
            const int32_t status = eosio::bls_g2_map(element, out);
            if(status != 0) return host_failure<eosio::bls_g2>(status);
            return result<eosio::bls_g2>::success(out);
        }

        inline result<eosio::bls_fp> fp_mod(const eosio::bls_s& value)
        {
            eosio::bls_fp out{};
            const int32_t status = eosio::bls_fp_mod(value, out);
            if(status != 0) return host_failure<eosio::bls_fp>(status);
            return result<eosio::bls_fp>::success(out);
        }

        inline result<eosio::bls_fp> fp_mul(const eosio::bls_fp& lhs, const eosio::bls_fp& rhs)
        {
            eosio::bls_fp out{};
            const int32_t status = eosio::bls_fp_mul(lhs, rhs, out);
            if(status != 0) return host_failure<eosio::bls_fp>(status);
            return result<eosio::bls_fp>::success(out);
        }

        inline result<eosio::bls_fp> fp_exp(const eosio::bls_fp& base, const eosio::bls_s& exponent)
        {
            eosio::bls_fp out{};
            const int32_t status = eosio::bls_fp_exp(base, exponent, out);
            if(status != 0) return host_failure<eosio::bls_fp>(status);
            return result<eosio::bls_fp>::success(out);
        }
    }
    inline std::array<uint64_t, 8> longScalarFromBytesBE(const std::array<uint8_t, 8*8>& in)
    {
        std::array<uint64_t, 8> out;
        for(uint64_t i = 0; i < 8; i++)
        {
            int64_t a = 8*8 - i*8;
            out[i] =
                static_cast<uint64_t>(in[a-1])       | static_cast<uint64_t>(in[a-2]) <<  8 |
                static_cast<uint64_t>(in[a-3]) << 16 | static_cast<uint64_t>(in[a-4]) << 24 |
                static_cast<uint64_t>(in[a-5]) << 32 | static_cast<uint64_t>(in[a-6]) << 40 |
                static_cast<uint64_t>(in[a-7]) << 48 | static_cast<uint64_t>(in[a-8]) << 56;
        }
        return out;
    }

    class scalar
    {
        public:
        uint64_t w0;
        uint64_t w1;
        uint64_t w2;
        uint64_t w3;
        EOSLIB_SERIALIZE(scalar, (w0)(w1)(w2)(w3))

        scalar() : w0(0), w1(0), w2(0), w3(0) {}
        scalar(const uint64_t& w0, const uint64_t& w1, const uint64_t& w2, const uint64_t& w3) : w0(w0), w1(w1), w2(w2), w3(w3) {}
        scalar(const std::array<uint64_t, 4>& d) : w0(d[0]), w1(d[1]), w2(d[2]), w3(d[3]) {}
        scalar(const scalar& e) : w0(e.w0), w1(e.w1), w2(e.w2), w3(e.w3) {}
        uint8_t* data()
        {
            return reinterpret_cast<uint8_t*>(&w0);
        }
        const uint8_t* data() const
        {
            return reinterpret_cast<const uint8_t*>(&w0);
        }
        operator std::array<uint64_t, 4>& ()
        {
            return *reinterpret_cast<std::array<uint64_t, 4>*>(&this->w0);
        }
        operator eosio::bls_scalar& ()
        {
            return *reinterpret_cast<eosio::bls_scalar*>(&this->w0);
        }
        operator const eosio::bls_scalar& () const
        {
            return *reinterpret_cast<const eosio::bls_scalar*>(&this->w0);
        }
        uint64_t& operator[](int i)
        {
            switch(i)
            {
                case 0: return w0;
                case 1: return w1;
                case 2: return w2;
                case 3: return w3;
                default:
                    eosio::check(false, "scalar limb index out of range");
                    return w0;
            }
        }
        const uint64_t& operator[](int i) const
        {
            switch(i)
            {
                case 0: return w0;
                case 1: return w1;
                case 2: return w2;
                case 3: return w3;
                default:
                    eosio::check(false, "scalar limb index out of range");
                    return w0;
            }
        }
        static scalar fromBytesLE(const std::span<const uint8_t, 4 * sizeof(uint64_t)>& in)
        {
            scalar out;
            memcpy(out.data(), in.data(), 4 * sizeof(uint64_t));
            return out;
        }
        static scalar fromBytesLE(const std::vector<uint8_t>& in)
        {
            eosio::check(in.size() >= 4 * sizeof(uint64_t), "scalar::fromBytesLE: expected at least 32 bytes");
            scalar out;
            memcpy(out.data(), in.data(), 4 * sizeof(uint64_t));
            return out;
        }
        // Interpret the four limbs as a *raw*, little-endian Fr wire integer.
        // This is NOT a Montgomery-domain predicate or modular reduction.
        bool isCanonicalRaw() const
        {
            if (w3 != Q.w3) return w3 < Q.w3;
            if (w2 != Q.w2) return w2 < Q.w2;
            if (w1 != Q.w1) return w1 < Q.w1;
            return w0 < Q.w0;
        }

        // Strict 32-byte little-endian Fr decoding. Unlike fromBytesLE(),
        // reject noncanonical wire values rather than reducing mod Q.
        static std::optional<scalar> tryFromCanonicalBytesLE(
            std::span<const uint8_t, 32> bytes)
        {
            scalar out;
            for (size_t i = 0; i < 4; ++i)
            {
                uint64_t limb = 0;
                for (size_t j = 0; j < 8; ++j)
                    limb |= static_cast<uint64_t>(bytes[i * 8 + j]) << (8 * j);
                out[static_cast<int>(i)] = limb;
            }
            if (!out.isCanonicalRaw()) return std::nullopt;
            return out;
        }

        // The vector overload enforces the *exact* wire length, not >=32.
        static std::optional<scalar> tryFromCanonicalBytesLE(
            const std::vector<uint8_t>& bytes)
        {
            if (bytes.size() != 32) return std::nullopt;
            return tryFromCanonicalBytesLE(
                std::span<const uint8_t, 32>(bytes.data(), 32));
        }
        bool equal(const scalar& e) const
        {
            return w0 == e.w0 && w1 == e.w1 && w2 == e.w2 && w3 == e.w3;
        }
        static scalar zero()
        {
            return scalar(0, 0, 0, 0);
        }
        static scalar one()
        {
            return R;
        }
        static scalar montgomery_reduce(
            uint64_t r0,
            uint64_t r1,
            uint64_t r2,
            uint64_t r3,
            uint64_t r4,
            uint64_t r5,
            uint64_t r6,
            uint64_t r7
        )
        {
            // The Montgomery reduction here is based on Algorithm 14.32 in
            // Handbook of Applied Cryptography: http://cacr.uwaterloo.ca/hac/about/chap14.pdf
            uint64_t k = r0 * INV;
            uint64_t carry = static_cast<uint64_t>((static_cast<uint128_t>(r0) + static_cast<uint128_t>(k) * static_cast<uint128_t>(Q.w0)) >> 64);
            uint128_t tmp = static_cast<uint128_t>(r1) + static_cast<uint128_t>(k) * static_cast<uint128_t>(Q.w1) + static_cast<uint128_t>(carry);
            r1 = static_cast<uint64_t>(tmp);
            carry = static_cast<uint64_t>(tmp >> 64);
            tmp = static_cast<uint128_t>(r2) + static_cast<uint128_t>(k) * static_cast<uint128_t>(Q.w2) + static_cast<uint128_t>(carry);
            r2 = static_cast<uint64_t>(tmp);
            carry = static_cast<uint64_t>(tmp >> 64);
            tmp = static_cast<uint128_t>(r3) + static_cast<uint128_t>(k) * static_cast<uint128_t>(Q.w3) + static_cast<uint128_t>(carry);
            r3 = static_cast<uint64_t>(tmp);
            carry = static_cast<uint64_t>(tmp >> 64);
            uint64_t t = r4 + carry;
            uint64_t carry2 = (t < r4);
            r4 = t;

            k = r1 * INV;
            carry = static_cast<uint64_t>((static_cast<uint128_t>(r1) + static_cast<uint128_t>(k) * static_cast<uint128_t>(Q.w0)) >> 64);
            tmp = static_cast<uint128_t>(r2) + static_cast<uint128_t>(k) * static_cast<uint128_t>(Q.w1) + static_cast<uint128_t>(carry);
            r2 = static_cast<uint64_t>(tmp);
            carry = static_cast<uint64_t>(tmp >> 64);
            tmp = static_cast<uint128_t>(r3) + static_cast<uint128_t>(k) * static_cast<uint128_t>(Q.w2) + static_cast<uint128_t>(carry);
            r3 = static_cast<uint64_t>(tmp);
            carry = static_cast<uint64_t>(tmp >> 64);
            tmp = static_cast<uint128_t>(r4) + static_cast<uint128_t>(k) * static_cast<uint128_t>(Q.w3) + static_cast<uint128_t>(carry);
            r4 = static_cast<uint64_t>(tmp);
            carry = static_cast<uint64_t>(tmp >> 64);
            t = r5 + carry2;
            uint64_t tt = t + carry;
            carry2 = (t < r5) + (tt < t);
            r5 = tt;

            k = r2 * INV;
            carry = static_cast<uint64_t>((static_cast<uint128_t>(r2) + static_cast<uint128_t>(k) * static_cast<uint128_t>(Q.w0)) >> 64);
            tmp = static_cast<uint128_t>(r3) + static_cast<uint128_t>(k) * static_cast<uint128_t>(Q.w1) + static_cast<uint128_t>(carry);
            r3 = static_cast<uint64_t>(tmp);
            carry = static_cast<uint64_t>(tmp >> 64);
            tmp = static_cast<uint128_t>(r4) + static_cast<uint128_t>(k) * static_cast<uint128_t>(Q.w2) + static_cast<uint128_t>(carry);
            r4 = static_cast<uint64_t>(tmp);
            carry = static_cast<uint64_t>(tmp >> 64);
            tmp = static_cast<uint128_t>(r5) + static_cast<uint128_t>(k) * static_cast<uint128_t>(Q.w3) + static_cast<uint128_t>(carry);
            r5 = static_cast<uint64_t>(tmp);
            carry = static_cast<uint64_t>(tmp >> 64);
            t = r6 + carry2;
            tt = t + carry;
            carry2 = (t < r6) + (tt < t);
            r6 = tt;

            k = r3 * INV;
            carry = static_cast<uint64_t>((static_cast<uint128_t>(r3) + static_cast<uint128_t>(k) * static_cast<uint128_t>(Q.w0)) >> 64);
            tmp = static_cast<uint128_t>(r4) + static_cast<uint128_t>(k) * static_cast<uint128_t>(Q.w1) + static_cast<uint128_t>(carry);
            r4 = static_cast<uint64_t>(tmp);
            carry = static_cast<uint64_t>(tmp >> 64);
            tmp = static_cast<uint128_t>(r5) + static_cast<uint128_t>(k) * static_cast<uint128_t>(Q.w2) + static_cast<uint128_t>(carry);
            r5 = static_cast<uint64_t>(tmp);
            carry = static_cast<uint64_t>(tmp >> 64);
            tmp = static_cast<uint128_t>(r6) + static_cast<uint128_t>(k) * static_cast<uint128_t>(Q.w3) + static_cast<uint128_t>(carry);
            r6 = static_cast<uint64_t>(tmp);
            carry = static_cast<uint64_t>(tmp >> 64);
            t = r7 + carry2;
            tt = t + carry;
            carry2 = (t < r7) + (tt < t);
            r7 = tt;

            // subtract modulus if result is greater than or equal Q
            if(r7 > Q.w3 || (r7 == Q.w3 && r6 > Q.w2) || (r7 == Q.w3 && r6 == Q.w2 && r5 > Q.w1) || (r7 == Q.w3 && r6 == Q.w2 && r5 == Q.w1 && r4 >= Q.w0))
            {
                return scalar(r4, r5, r6, r7).sub(Q);
            }
            return scalar(r4, r5, r6, r7);
        }
        scalar mul(const scalar& rhs) const
        {
            uint128_t tmp = static_cast<uint128_t>(w0) * static_cast<uint128_t>(rhs.w0);
            uint64_t r0 = static_cast<uint64_t>(tmp);
            uint64_t carry = static_cast<uint64_t>(tmp >> 64);
            tmp = static_cast<uint128_t>(w0) * static_cast<uint128_t>(rhs.w1) + static_cast<uint128_t>(carry);
            uint64_t r1 = static_cast<uint64_t>(tmp);
            carry = static_cast<uint64_t>(tmp >> 64);
            tmp = static_cast<uint128_t>(w0) * static_cast<uint128_t>(rhs.w2) + static_cast<uint128_t>(carry);
            uint64_t r2 = static_cast<uint64_t>(tmp);
            carry = static_cast<uint64_t>(tmp >> 64);
            tmp = static_cast<uint128_t>(w0) * static_cast<uint128_t>(rhs.w3) + static_cast<uint128_t>(carry);
            uint64_t r3 = static_cast<uint64_t>(tmp);
            uint64_t r4 = static_cast<uint64_t>(tmp >> 64);

            tmp = static_cast<uint128_t>(r1) + static_cast<uint128_t>(w1) * static_cast<uint128_t>(rhs.w0);
            r1 = static_cast<uint64_t>(tmp);
            carry = static_cast<uint64_t>(tmp >> 64);
            tmp = static_cast<uint128_t>(r2) + static_cast<uint128_t>(w1) * static_cast<uint128_t>(rhs.w1) + static_cast<uint128_t>(carry);
            r2 = static_cast<uint64_t>(tmp);
            carry = static_cast<uint64_t>(tmp >> 64);
            tmp = static_cast<uint128_t>(r3) + static_cast<uint128_t>(w1) * static_cast<uint128_t>(rhs.w2) + static_cast<uint128_t>(carry);
            r3 = static_cast<uint64_t>(tmp);
            carry = static_cast<uint64_t>(tmp >> 64);
            tmp = static_cast<uint128_t>(r4) + static_cast<uint128_t>(w1) * static_cast<uint128_t>(rhs.w3) + static_cast<uint128_t>(carry);
            r4 = static_cast<uint64_t>(tmp);
            uint64_t r5 = static_cast<uint64_t>(tmp >> 64);

            tmp = static_cast<uint128_t>(r2) + static_cast<uint128_t>(w2) * static_cast<uint128_t>(rhs.w0);
            r2 = static_cast<uint64_t>(tmp);
            carry = static_cast<uint64_t>(tmp >> 64);
            tmp = static_cast<uint128_t>(r3) + static_cast<uint128_t>(w2) * static_cast<uint128_t>(rhs.w1) + static_cast<uint128_t>(carry);
            r3 = static_cast<uint64_t>(tmp);
            carry = static_cast<uint64_t>(tmp >> 64);
            tmp = static_cast<uint128_t>(r4) + static_cast<uint128_t>(w2) * static_cast<uint128_t>(rhs.w2) + static_cast<uint128_t>(carry);
            r4 = static_cast<uint64_t>(tmp);
            carry = static_cast<uint64_t>(tmp >> 64);
            tmp = static_cast<uint128_t>(r5) + static_cast<uint128_t>(w2) * static_cast<uint128_t>(rhs.w3) + static_cast<uint128_t>(carry);
            r5 = static_cast<uint64_t>(tmp);
            uint64_t r6 = static_cast<uint64_t>(tmp >> 64);

            tmp = static_cast<uint128_t>(r3) + static_cast<uint128_t>(w3) * static_cast<uint128_t>(rhs.w0);
            r3 = static_cast<uint64_t>(tmp);
            carry = static_cast<uint64_t>(tmp >> 64);
            tmp = static_cast<uint128_t>(r4) + static_cast<uint128_t>(w3) * static_cast<uint128_t>(rhs.w1) + static_cast<uint128_t>(carry);
            r4 = static_cast<uint64_t>(tmp);
            carry = static_cast<uint64_t>(tmp >> 64);
            tmp = static_cast<uint128_t>(r5) + static_cast<uint128_t>(w3) * static_cast<uint128_t>(rhs.w2) + static_cast<uint128_t>(carry);
            r5 = static_cast<uint64_t>(tmp);
            carry = static_cast<uint64_t>(tmp >> 64);
            tmp = static_cast<uint128_t>(r6) + static_cast<uint128_t>(w3) * static_cast<uint128_t>(rhs.w3) + static_cast<uint128_t>(carry);
            r6 = static_cast<uint64_t>(tmp);
            uint64_t r7 = static_cast<uint64_t>(tmp >> 64);

            return montgomery_reduce(r0, r1, r2, r3, r4, r5, r6, r7);
        }
        scalar add(const scalar& rhs) const
        {
            uint64_t d0 = w0 + rhs.w0;
            uint64_t carry = (d0 < w0);
            uint64_t tmp = w1 + carry;
            uint64_t d1 = tmp + rhs.w1;
            carry = (tmp < w1) + (d1 < tmp);
            tmp = w2 + carry;
            uint64_t d2 = tmp + rhs.w2;
            carry = (tmp < w2) + (d2 < tmp);
            tmp = w3 + carry;
            uint64_t d3 = tmp + rhs.w3;

            // subtract modulus if result is greater than or equal Q
            if(d3 > Q.w3 || (d3 == Q.w3 && d2 > Q.w2) || (d3 == Q.w3 && d2 == Q.w2 && d1 > Q.w1) || (d3 == Q.w3 && d2 == Q.w2 && d1 == Q.w1 && d0 >= Q.w0))
            {
                return scalar(d0, d1, d2, d3).sub(Q);
            }
            return scalar(d0, d1, d2, d3);
        }
        scalar sub(const scalar& rhs) const
        {
            uint64_t d0 = w0 - rhs.w0;
            uint64_t borrow = d0 > w0;
            uint64_t tmp = w1 - borrow;
            uint64_t d1 = tmp - rhs.w1;
            borrow = (tmp > w1) + (d1 > tmp);
            tmp = w2 - borrow;
            uint64_t d2 = tmp - rhs.w2;
            borrow = (tmp > w2) + (d2 > tmp);
            tmp = w3 - borrow;
            uint64_t d3 = tmp - rhs.w3;
            borrow = (tmp > w3) + (d3 > tmp);

            // if underflow occurred add modulus
            if(borrow > 0)
            {
                uint64_t e0 = d0 + Q.w0;
                uint64_t carry = (e0 < d0);
                tmp = d1 + carry;
                uint64_t e1 = tmp + Q.w1;
                carry = (tmp < d1) + (e1 < tmp);
                tmp = d2 + carry;
                uint64_t e2 = tmp + Q.w2;
                carry = (tmp < d2) + (e2 < tmp);
                tmp = d3 + carry;
                uint64_t e3 = tmp + Q.w3;

                return scalar(e0, e1, e2, e3);
            }

            return scalar(d0, d1, d2, d3);
        }

        static const scalar Q;          // Constant representing the modulus q = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
        static const uint64_t INV;      // INV = -(q^{-1} mod 2^64) mod 2^64
        static const scalar R;          // R = 2^256 mod q
        static const scalar EDWARDS_D2; // Jubjub: 2*d with d = -(10240/10241)
    };
    inline const scalar scalar::Q = {
        0xffff'ffff'0000'0001,
        0x53bd'a402'fffe'5bfe,
        0x3339'd808'09a1'd805,
        0x73ed'a753'299d'7d48
    };
    inline const uint64_t scalar::INV = 0xFFFF'FFFE'FFFF'FFFF;
    inline const scalar scalar::R = {
        0x0000'0001'ffff'fffe,
        0x5884'b7fa'0003'4802,
        0x998c'4fef'ecbc'4ff5,
        0x1824'b159'acc5'056f
    };
    inline const scalar scalar::EDWARDS_D2 = {
        0x54A4'48AC'72E9'ED5F,
        0xA51B'EFDB'1B37'3967,
        0xC0D8'1F21'7B4A'799E,
        0x3C04'45FE'D27E'CF14
    };

    class fp
    {
        public:
        uint64_t w0;
        uint64_t w1;
        uint64_t w2;
        uint64_t w3;
        uint64_t w4;
        uint64_t w5;
        EOSLIB_SERIALIZE(fp, (w0)(w1)(w2)(w3)(w4)(w5))

        fp() : w0(0), w1(0), w2(0), w3(0), w4(0), w5(0) {}
        fp(const uint64_t& w0, const uint64_t& w1, const uint64_t& w2, const uint64_t& w3, const uint64_t& w4, const uint64_t& w5) : w0(w0), w1(w1), w2(w2), w3(w3), w4(w4), w5(w5) {}
        fp(const std::array<uint64_t, 6>& d) : w0(d[0]), w1(d[1]), w2(d[2]), w3(d[3]), w4(d[4]), w5(d[5]) {}
        fp(const fp& e) : w0(e.w0), w1(e.w1), w2(e.w2), w3(e.w3), w4(e.w4), w5(e.w5) {}
        uint8_t* data()
        {
            return reinterpret_cast<uint8_t*>(&w0);
        }
        const uint8_t* data() const
        {
            return reinterpret_cast<const uint8_t*>(&w0);
        }
        operator std::array<uint64_t, 6>& ()
        {
            return *reinterpret_cast<std::array<uint64_t, 6>*>(&this->w0);
        }
        operator eosio::bls_fp& ()
        {
            return *reinterpret_cast<eosio::bls_fp*>(&this->w0);
        }
        operator const eosio::bls_fp& () const
        {
            return *reinterpret_cast<const eosio::bls_fp*>(&this->w0);
        }
        uint64_t& operator[](int i)
        {
            switch(i)
            {
                case 0: return w0;
                case 1: return w1;
                case 2: return w2;
                case 3: return w3;
                case 4: return w4;
                case 5: return w5;
                default:
                    eosio::check(false, "fp limb index out of range");
                    return w0;
            }
        }
        const uint64_t& operator[](int i) const
        {
            switch(i)
            {
                case 0: return w0;
                case 1: return w1;
                case 2: return w2;
                case 3: return w3;
                case 4: return w4;
                case 5: return w5;
                default:
                    eosio::check(false, "fp limb index out of range");
                    return w0;
            }
        }
        static fp fromBytesLE(const std::span<const uint8_t, 6 * sizeof(uint64_t)>& in)
        {
            fp out;
            memcpy(out.data(), in.data(), 6 * sizeof(uint64_t));
            return out;
        }
        static fp zero()
        {
            return fp(0, 0, 0, 0, 0, 0);
        }
        static fp one()
        {
            return R1;
        }
        bool isValid() const
        {
            return cmp(MODULUS) < 0;
        }
        bool isOdd() const
        {
            return (w0 & 1) != 0;
        }
        bool isEven() const
        {
            return (w0 & 1) == 0;
        }
        bool isZero() const
        {
            return (w5 | w4 | w3 | w2 | w1 | w0) == 0;
        }
        bool isOne() const
        {
            return equal(R1);
        }
        int64_t cmp(const fp& e) const
        {
            for(int64_t i = 5; i >= 0; i--)
            {
                if((&w0)[i] < (&e.w0)[i])
                {
                    return -1;
                }
                if((&w0)[i] > (&e.w0)[i])
                {
                    return 1;
                }
            }
            return 0;
        }
        bool equal(const fp& e) const
        {
            return w0 == e.w0 && w1 == e.w1 && w2 == e.w2 && w3 == e.w3 && w4 == e.w4 && w5 == e.w5;
        }
        fp neg() const
        {
            if(isZero())
            {
                return *this;
            }
            fp z;
            z.w0 = fp::MODULUS.w0 - w0;
            uint64_t borrow = z.w0 > fp::MODULUS.w0;
            uint64_t tmp = fp::MODULUS.w1 - borrow;
            z.w1 = tmp - w1;
            borrow = (tmp > fp::MODULUS.w1) + (z.w1 > tmp);
            tmp = fp::MODULUS.w2 - borrow;
            z.w2 = tmp - w2;
            borrow = (tmp > fp::MODULUS.w2) + (z.w2 > tmp);
            tmp = fp::MODULUS.w3 - borrow;
            z.w3 = tmp - w3;
            borrow = (tmp > fp::MODULUS.w3) + (z.w3 > tmp);
            tmp = fp::MODULUS.w4 - borrow;
            z.w4 = tmp - w4;
            borrow = (tmp > fp::MODULUS.w4) + (z.w4 > tmp);
            tmp = fp::MODULUS.w5 - borrow;
            z.w5 = tmp - w5;
            return z;
        }
        static fp modPrime(const std::array<uint64_t, 8>& k)
        {
            fp out;
            const int32_t status = eosio::bls_fp_mod(*reinterpret_cast<const eosio::bls_s*>(&k), out);
            eosio::check(status == 0, "fp::modPrime: bls_fp_mod failed");
            return out;
        }

        static const fp MODULUS;
        static const fp R1;
    };
    inline const fp fp::MODULUS = fp(
        0xb9fe'ffff'ffff'aaab,
        0x1eab'fffe'b153'ffff,
        0x6730'd2a0'f6b0'f624,
        0x6477'4b84'f385'12bf,
        0x4b1b'a7b6'434b'acd7,
        0x1a01'11ea'397f'e69a
    );
    //inline const fp fp::R1 = fp(
    //    0x7609'0000'0002'fffd,
    //    0xebf4'000b'c40c'0002,
    //    0x5f48'9857'53c7'58ba,
    //    0x77ce'5853'7052'5745,
    //    0x5c07'1a97'a256'ec6d,
    //    0x15f6'5ec3'fa80'e493
    //);
    // montgomery encoding
    inline const fp fp::R1 = fp(
        0x0000'0000'0000'0001,
        0x0000'0000'0000'0000,
        0x0000'0000'0000'0000,
        0x0000'0000'0000'0000,
        0x0000'0000'0000'0000,
        0x0000'0000'0000'0000
    );

    class fp2
    {
        public:
        fp c0;
        fp c1;
        EOSLIB_SERIALIZE(fp2, (c0)(c1))

        fp2() : c0(fp()), c1(fp()) {}
        fp2(const fp& c0, const fp& c1) : c0(c0), c1(c1) {}
        fp2(const std::array<fp, 2>& d) : c0(d[0]), c1(d[1]) {}
        fp2(const fp2& e) : c0(e.c0), c1(e.c1) {}
        uint8_t* data()
        {
            return c0.data();
        }
        const uint8_t* data() const
        {
            return c0.data();
        }
        operator eosio::bls_fp2& ()
        {
            return *reinterpret_cast<eosio::bls_fp2*>(&this->c0.w0);
        }
        operator const eosio::bls_fp2& () const
        {
            return *reinterpret_cast<const eosio::bls_fp2*>(&this->c0.w0);
        }
        static fp2 fromBytesLE(const std::span<const uint8_t, 2 * sizeof(fp)>& in)
        {
            fp2 out;
            memcpy(out.data(), in.data(), 2 * sizeof(fp));
            return out;
        }
        static fp2 zero()
        {
            return fp2(fp::zero(), fp::zero());
        }
        static fp2 one()
        {
             return fp2(fp::one(), fp::zero());
        }
        bool isZero() const
        {
            return c0.isZero() && c1.isZero();
        }
        bool isOne() const
        {
            return c0.isOne() && c1.isZero();
        }
        fp2 neg() const
        {
            return fp2(c0.neg(), c1.neg());
        }
        bool equal(const fp2& e) const
        {
            return c0.equal(e.c0) && c1.equal(e.c1);
        }
    };

    class fp6
    {
        public:
        fp2 c0;
        fp2 c1;
        fp2 c2;
        EOSLIB_SERIALIZE(fp6, (c0)(c1)(c2))

        fp6() : c0(fp2()), c1(fp2()), c2(fp2()) {}
        fp6(const fp2& c0, const fp2& c1, const fp2& c2) : c0(c0), c1(c1), c2(c2) {}
        fp6(const std::array<fp2, 3>& d) : c0(d[0]), c1(d[1]), c2(d[2]) {}
        fp6(const fp6& e) : c0(e.c0), c1(e.c1), c2(e.c2) {}
        uint8_t* data()
        {
            return c0.data();
        }
        const uint8_t* data() const
        {
            return c0.data();
        }
        static fp6 fromBytesLE(const std::span<const uint8_t, 3 * sizeof(fp2)>& in)
        {
            fp6 out;
            memcpy(out.data(), in.data(), 3 * sizeof(fp2));
            return out;
        }
        static fp6 zero()
        {
            return fp6(fp2::zero(), fp2::zero(), fp2::zero());
        }
        static fp6 one()
        {
            return fp6(fp2::one(), fp2::zero(), fp2::zero());
        }
        bool equal(const fp6& e) const
        {
            return c0.equal(e.c0) && c1.equal(e.c1) && c2.equal(e.c2);
        }
    };

    class fp12
    {
        public:
        fp6 c0;
        fp6 c1;
        EOSLIB_SERIALIZE(fp12, (c0)(c1))

        fp12() : c0(fp6()), c1(fp6()) {}
        fp12(const fp6& c0, const fp6& c1) : c0(c0), c1(c1) {}
        fp12(const std::array<fp6, 2>& d) : c0(d[0]), c1(d[1]) {}
        fp12(const fp12& e) : c0(e.c0), c1(e.c1) {}
        uint8_t* data()
        {
            return c0.data();
        }
        const uint8_t* data() const
        {
            return c0.data();
        }
        operator eosio::bls_gt& ()
        {
            return *reinterpret_cast<eosio::bls_gt*>(&this->c0.c0.c0.w0);
        }
        operator const eosio::bls_gt& () const
        {
            return *reinterpret_cast<const eosio::bls_gt*>(&this->c0.c0.c0.w0);
        }
        static fp12 fromBytesLE(const std::span<const uint8_t, 2 * sizeof(fp6)>& in)
        {
            fp12 out;
            memcpy(out.data(), in.data(), 2 * sizeof(fp6));
            return out;
        }
        static fp12 zero()
        {
            return fp12(fp6::zero(), fp6::zero());
        }
        static fp12 one()
        {
            return fp12(fp6::one(), fp6::zero());
        }
        bool equal(const fp12& e) const
        {
            return c0.equal(e.c0) && c1.equal(e.c1);
        }
    };

    // affine g1 type
    class g1
    {
        public:
        fp x;
        fp y;
        EOSLIB_SERIALIZE(g1, (x)(y))

        g1() : x(fp()), y(fp()) {}
        g1(const fp& x, const fp& y) : x(x), y(y) {}
        g1(const std::array<fp, 2>& d) : x(d[0]), y(d[1]) {}
        g1(const g1& e) : x(e.x), y(e.y) {}
        uint8_t* data()
        {
            return x.data();
        }
        const uint8_t* data() const
        {
            return x.data();
        }
        operator eosio::bls_g1& ()
        {
            return *reinterpret_cast<eosio::bls_g1*>(&this->x.w0);
        }
        operator const eosio::bls_g1& () const
        {
            return *reinterpret_cast<const eosio::bls_g1*>(&this->x.w0);
        }
        static g1 fromAffineBytesLE(const std::span<const uint8_t, 2 * sizeof(fp)> in)
        {
            fp x = fp::fromBytesLE(std::span<const uint8_t, sizeof(fp)>(&in[ 0], &in[ 48]));
            fp y = fp::fromBytesLE(std::span<const uint8_t, sizeof(fp)>(&in[48], &in[ 96]));
            g1 p = g1(x, y);
            return p;
        }
        std::array<uint8_t, sizes::g1_affine_le_bytes> toAffineBytesLE() const
        {
            std::array<uint8_t, sizes::g1_affine_le_bytes> out{};
            memcpy(out.data(), data(), out.size());
            return out;
        }
        bool isIdentity() const
        {
            return x.isZero() && y.isZero();
        }
        static g1 one()
        {
            return BASE;
        }
        g1 add(const g1& e) const
        {
            g1 out;
            const int32_t status = eosio::bls_g1_add(*this, e, out);
            eosio::check(status == 0, "g1::add: bls_g1_add failed");
            return out;
        }
        g1 dbl() const
        {
            return this->add(*this);
        }
        g1 neg() const
        {
            return g1(x, y.neg());
        }
        g1 sub(const g1& e) const
        {
            g1 c, d;
            d = e.neg();
            c = this->add(d);
            return c;
        }
        g1 clearCofactor() const
        {
            return mulScalar(cofactorEFF);
        }
        g1 mulScalar(const scalar& s) const
        {
            g1 out;
            const int32_t status = eosio::bls_g1_weighted_sum(
                reinterpret_cast<const eosio::bls_g1*>(this->data()),
                reinterpret_cast<const eosio::bls_scalar*>(s.data()),
                1,
                out
            );
            eosio::check(status == 0, "g1::mulScalar: bls_g1_weighted_sum failed");
            return out;
        }
        static g1 multiExp(const g1 points[], const scalar scalars[], const uint32_t num)
        {
            eosio::check(
                host_detail::valid_count_for_host(num, sizeof(eosio::bls_g1)) &&
                host_detail::valid_count_for_host(num, sizeof(eosio::bls_scalar)),
                "g1::multiExp: invalid point count"
            );
            g1 out;
            const int32_t status = eosio::bls_g1_weighted_sum(
                reinterpret_cast<const eosio::bls_g1*>(points),
                reinterpret_cast<const eosio::bls_scalar*>(scalars),
                num,
                out
            );
            eosio::check(status == 0, "g1::multiExp: bls_g1_weighted_sum failed");
            return out;
        }
        static g1 mapToCurve(const fp& e)
        {
            g1 out;
            const int32_t status = eosio::bls_g1_map(e, out);
            eosio::check(status == 0, "g1::mapToCurve: bls_g1_map failed");
            return out;
        }

        static const g1 BASE;
        static const g1 BASE_NEG;
        static const scalar cofactorEFF;
    };
    // affine, montgomery encoded
    inline const g1 g1::BASE = g1(
        fp(0xfb3af00adb22c6bb, 0x6c55e83ff97a1aef, 0xa14e3a3f171bac58, 0xc3688c4f9774b905, 0x2695638c4fa9ac0f, 0x17f1d3a73197d794),
        fp(0x0caa232946c5e7e1, 0xd03cc744a2888ae4, 0x00db18cb2c04b3ed, 0xfcf5e095d5d00af6, 0xa09e30ed741d8ae4, 0x08b3f481e3aaa0f1)
    );
    inline const g1 g1::BASE_NEG = g1(
        fp(0xfb3af00adb22c6bb, 0x6c55e83ff97a1aef, 0xa14e3a3f171bac58, 0xc3688c4f9774b905, 0x2695638c4fa9ac0f, 0x17f1d3a73197d794),
        fp(0xad54dcd6b939c2ca, 0x4e6f38ba0ecb751b, 0x6655b9d5caac4236, 0x67816aef1db507c9, 0xaa7d76c8cf2e21f2, 0x114d1d6855d545a8)
    );
    inline const scalar g1::cofactorEFF = {0xd201000000010001, 0, 0, 0};

    // affine g2 type
    class g2
    {
        public:
        fp2 x;
        fp2 y;
        EOSLIB_SERIALIZE(g2, (x)(y))

        g2() : x(fp2()), y(fp2()) {}
        g2(const fp2& x, const fp2& y) : x(x), y(y) {}
        g2(const std::array<fp2, 2>& d) : x(d[0]), y(d[1]) {}
        g2(const g2& e) : x(e.x), y(e.y) {}
        uint8_t* data()
        {
            return x.data();
        }
        const uint8_t* data() const
        {
            return x.data();
        }
        operator eosio::bls_g2& ()
        {
            return *reinterpret_cast<eosio::bls_g2*>(&this->x.c0.w0);
        }
        operator const eosio::bls_g2& () const
        {
            return *reinterpret_cast<const eosio::bls_g2*>(&this->x.c0.w0);
        }
        static g2 fromAffineBytesLE(const std::span<const uint8_t, 2 * sizeof(fp2)> in)
        {
            fp2 x = fp2::fromBytesLE(std::span<const uint8_t, sizeof(fp2)>(&in[ 0], &in[ 96]));
            fp2 y = fp2::fromBytesLE(std::span<const uint8_t, sizeof(fp2)>(&in[96], &in[192]));
            g2 p = g2(x, y);
            return p;
        }
        std::array<uint8_t, sizes::g2_affine_le_bytes> toAffineBytesLE() const
        {
            std::array<uint8_t, sizes::g2_affine_le_bytes> out{};
            memcpy(out.data(), data(), out.size());
            return out;
        }
        bool isIdentity() const
        {
            return x.isZero() && y.isZero();
        }
        static g2 one()
        {
            return BASE;
        }
        g2 add(const g2& e) const
        {
            g2 out;
            const int32_t status = eosio::bls_g2_add(*this, e, out);
            eosio::check(status == 0, "g2::add: bls_g2_add failed");
            return out;
        }
        g2 dbl() const
        {
            return this->add(*this);
        }
        g2 neg() const
        {
            return g2(x, y.neg());
        }
        g2 sub(const g2& e) const
        {
            g2 c, d;
            d = e.neg();
            c = this->add(d);
            return c;
        }
        g2 mulScalar(const scalar& s) const
        {
            g2 out;
            const int32_t status = eosio::bls_g2_weighted_sum(
                reinterpret_cast<const eosio::bls_g2*>(this->data()),
                reinterpret_cast<const eosio::bls_scalar*>(s.data()),
                1,
                out
            );
            eosio::check(status == 0, "g2::mulScalar: bls_g2_weighted_sum failed");
            return out;
        }
        static g2 multiExp(const g2 points[], const scalar scalars[], const uint32_t num)
        {
            eosio::check(
                host_detail::valid_count_for_host(num, sizeof(eosio::bls_g2)) &&
                host_detail::valid_count_for_host(num, sizeof(eosio::bls_scalar)),
                "g2::multiExp: invalid point count"
            );
            g2 out;
            const int32_t status = eosio::bls_g2_weighted_sum(
                reinterpret_cast<const eosio::bls_g2*>(points),
                reinterpret_cast<const eosio::bls_scalar*>(scalars),
                num,
                out
            );
            eosio::check(status == 0, "g2::multiExp: bls_g2_weighted_sum failed");
            return out;
        }
        static g2 mapToCurve(const fp2& e)
        {
            g2 out;
            const int32_t status = eosio::bls_g2_map(e, out);
            eosio::check(status == 0, "g2::mapToCurve: bls_g2_map failed");
            return out;
        }

        static const g2 BASE;
    };
    // affine, montgomery encoded
    inline const g2 g2::BASE = g2(
        fp2(
            fp(0xd48056c8c121bdb8, 0x0bac0326a805bbef, 0xb4510b647ae3d177, 0xc6e47ad4fa403b02, 0x260805272dc51051, 0x024aa2b2f08f0a91),
            fp(0xe5ac7d055d042b7e, 0x334cf11213945d57, 0xb5da61bbdc7f5049, 0x596bd0d09920b61a, 0x7dacd3a088274f65, 0x13e02b6052719f60)
        ),
        fp2(
            fp(0xe193548608b82801, 0x923ac9cc3baca289, 0x6d429a695160d12c, 0xadfd9baa8cbdd3a7, 0x8cc9cdc6da2e351a, 0x0ce5d527727d6e11),
            fp(0xaaa9075ff05f79be, 0x3f370d275cec1da1, 0x267492ab572e99ab, 0xcb3e287e85a763af, 0x32acd2b02bc28b99, 0x0606c4a02ea734cc)
        )
    );

    class validated_g1_affine_le
    {
        public:
        static result<validated_g1_affine_le> from_point(const g1& point)
        {
            eosio::bls_g1 host_point{};
            memcpy(host_point.data(), point.data(), host_point.size());
            const eosio::bls_g1 identity{};

            // Addition with the identity asks the host to parse, canonicalize and
            // curve-check the affine input without changing the represented point.
            const auto canonical = host_detail::g1_add(host_point, identity);
            if(!canonical)
            {
                return result<validated_g1_affine_le>::failure(
                    bls_errc::malformed_g1,
                    canonical.error().host_status
                );
            }

            g1 checked_point;
            memcpy(checked_point.data(), canonical.value().data(), sizeof(g1));
            if(checked_point.isIdentity())
            {
                return result<validated_g1_affine_le>::failure(bls_errc::identity_point);
            }

            eosio::bls_scalar group_order{};
            memcpy(group_order.data(), scalar::Q.data(), group_order.size());
            const auto subgroup_product = host_detail::g1_weighted_sum(
                &canonical.value(),
                &group_order,
                1
            );
            if(!subgroup_product)
            {
                return result<validated_g1_affine_le>::failure(
                    bls_errc::host_operation_failed,
                    subgroup_product.error().host_status
                );
            }

            g1 subgroup_check;
            memcpy(subgroup_check.data(), subgroup_product.value().data(), sizeof(g1));
            if(!subgroup_check.isIdentity())
            {
                return result<validated_g1_affine_le>::failure(bls_errc::wrong_subgroup);
            }

            return result<validated_g1_affine_le>::success(validated_g1_affine_le(checked_point));
        }

        static result<validated_g1_affine_le> fromAffineBytesLE(const std::span<const uint8_t> bytes)
        {
            if(bytes.size() != sizes::g1_affine_le_bytes)
            {
                return result<validated_g1_affine_le>::failure(bls_errc::invalid_length);
            }
            return from_point(g1::fromAffineBytesLE(
                std::span<const uint8_t, sizes::g1_affine_le_bytes>(bytes.data(), sizes::g1_affine_le_bytes)
            ));
        }

        const g1& point() const
        {
            return point_;
        }

        std::array<uint8_t, sizes::g1_affine_le_bytes> toAffineBytesLE() const
        {
            return point_.toAffineBytesLE();
        }

        private:
        explicit validated_g1_affine_le(const g1& point) : point_(point) {}

        static validated_g1_affine_le from_trusted_point(const g1& point)
        {
            return validated_g1_affine_le(point);
        }

        g1 point_;

        friend result<validated_g1_affine_le> aggregate_public_keys(
            std::span<const validated_g1_affine_le> keys
        );
    };

    class validated_g2_affine_le
    {
        public:
        static result<validated_g2_affine_le> from_point(const g2& point)
        {
            eosio::bls_g2 host_point{};
            memcpy(host_point.data(), point.data(), host_point.size());
            const eosio::bls_g2 identity{};

            const auto canonical = host_detail::g2_add(host_point, identity);
            if(!canonical)
            {
                return result<validated_g2_affine_le>::failure(
                    bls_errc::malformed_g2,
                    canonical.error().host_status
                );
            }

            g2 checked_point;
            memcpy(checked_point.data(), canonical.value().data(), sizeof(g2));
            if(checked_point.isIdentity())
            {
                return result<validated_g2_affine_le>::failure(bls_errc::identity_point);
            }

            eosio::bls_scalar group_order{};
            memcpy(group_order.data(), scalar::Q.data(), group_order.size());
            const auto subgroup_product = host_detail::g2_weighted_sum(
                &canonical.value(),
                &group_order,
                1
            );
            if(!subgroup_product)
            {
                return result<validated_g2_affine_le>::failure(
                    bls_errc::host_operation_failed,
                    subgroup_product.error().host_status
                );
            }

            g2 subgroup_check;
            memcpy(subgroup_check.data(), subgroup_product.value().data(), sizeof(g2));
            if(!subgroup_check.isIdentity())
            {
                return result<validated_g2_affine_le>::failure(bls_errc::wrong_subgroup);
            }

            return result<validated_g2_affine_le>::success(validated_g2_affine_le(checked_point));
        }

        static result<validated_g2_affine_le> fromAffineBytesLE(const std::span<const uint8_t> bytes)
        {
            if(bytes.size() != sizes::g2_affine_le_bytes)
            {
                return result<validated_g2_affine_le>::failure(bls_errc::invalid_length);
            }
            return from_point(g2::fromAffineBytesLE(
                std::span<const uint8_t, sizes::g2_affine_le_bytes>(bytes.data(), sizes::g2_affine_le_bytes)
            ));
        }

        const g2& point() const
        {
            return point_;
        }

        std::array<uint8_t, sizes::g2_affine_le_bytes> toAffineBytesLE() const
        {
            return point_.toAffineBytesLE();
        }

        private:
        explicit validated_g2_affine_le(const g2& point) : point_(point) {}

        static validated_g2_affine_le from_trusted_point(const g2& point)
        {
            return validated_g2_affine_le(point);
        }

        g2 point_;

        friend result<validated_g2_affine_le> hash_to_g2(
            std::span<const uint8_t> message,
            std::string_view dst
        );
    };

    using binary_message_view = std::span<const uint8_t>;


    namespace pairing
    {
        inline fp12 calculate(const g1 g1_points[], const g2 g2_points[], const uint32_t num)
        {
            eosio::check(
                host_detail::valid_count_for_host(num, sizeof(eosio::bls_g1)) &&
                host_detail::valid_count_for_host(num, sizeof(eosio::bls_g2)),
                "pairing::calculate: invalid point count"
            );
            fp12 f;
            const int32_t status = eosio::bls_pairing(
                reinterpret_cast<const eosio::bls_g1*>(g1_points),
                reinterpret_cast<const eosio::bls_g2*>(g2_points),
                num,
                f
            );
            eosio::check(status == 0, "pairing::calculate: bls_pairing failed");
            return f;
        }
    }

    // expand_message_xmd using SHA-256, following the same byte construction as
    // the previous bundled SHA-256 implementation while delegating hashing to Leap.
    inline void xmd_sh256(
        uint8_t *buf,
        int buf_len,
        const uint8_t *in,
        int in_len,
        const uint8_t *dst,
        int dst_len
    )
    {
        constexpr size_t SHA256HashSize = 32;
        constexpr size_t SHA256MessageBlockSize = 64;

        eosio::check(buf_len >= 0, "xmd_sh256: negative output length");
        eosio::check(in_len >= 0, "xmd_sh256: negative input length");
        eosio::check(dst_len >= 0 && dst_len <= 255, "xmd_sh256: invalid DST length");
        eosio::check(buf != nullptr || buf_len == 0, "xmd_sh256: null output buffer");
        eosio::check(in != nullptr || in_len == 0, "xmd_sh256: null input buffer");
        eosio::check(dst != nullptr || dst_len == 0, "xmd_sh256: null DST buffer");

        const size_t output_len = static_cast<size_t>(buf_len);
        const size_t ell = (output_len + SHA256HashSize - 1) / SHA256HashSize;
        eosio::check(ell <= 255, "xmd_sh256: output length too large");
        if(output_len == 0)
        {
            return;
        }

        const uint8_t l_i_b_str[2] = {
            static_cast<uint8_t>(output_len >> 8),
            static_cast<uint8_t>(output_len & 0xff)
        };
        const uint8_t dst_len_byte = static_cast<uint8_t>(dst_len);

        std::vector<uint8_t> b0_input;
        b0_input.reserve(SHA256MessageBlockSize + static_cast<size_t>(in_len) + 3 + static_cast<size_t>(dst_len) + 1);
        b0_input.insert(b0_input.end(), SHA256MessageBlockSize, 0);
        if(in_len > 0)
        {
            b0_input.insert(b0_input.end(), in, in + in_len);
        }
        b0_input.push_back(l_i_b_str[0]);
        b0_input.push_back(l_i_b_str[1]);
        b0_input.push_back(0);
        if(dst_len > 0)
        {
            b0_input.insert(b0_input.end(), dst, dst + dst_len);
        }
        b0_input.push_back(dst_len_byte);

        const std::array<uint8_t, SHA256HashSize> b0 = bls12_381_cdt_detail::sha256Digest(b0_input);
        std::array<uint8_t, SHA256HashSize> bi{};

        for(size_t i = 1; i <= ell; ++i)
        {
            std::vector<uint8_t> bi_input;
            bi_input.reserve(SHA256HashSize + 1 + static_cast<size_t>(dst_len) + 1);
            for(size_t j = 0; j < SHA256HashSize; ++j)
            {
                bi_input.push_back(static_cast<uint8_t>(b0[j] ^ bi[j]));
            }
            bi_input.push_back(static_cast<uint8_t>(i));
            if(dst_len > 0)
            {
                bi_input.insert(bi_input.end(), dst, dst + dst_len);
            }
            bi_input.push_back(dst_len_byte);

            bi = bls12_381_cdt_detail::sha256Digest(bi_input);

            const size_t offset = (i - 1) * SHA256HashSize;
            const size_t copy_len = std::min(SHA256HashSize, output_len - offset);
            memcpy(buf + offset, bi.data(), copy_len);
        }
    }

    inline result<validated_g2_affine_le> hash_to_g2(
        const std::span<const uint8_t> message,
        const std::string_view dst
    )
    {
        if(message.size() > static_cast<size_t>(std::numeric_limits<int>::max()))
        {
            return result<validated_g2_affine_le>::failure(bls_errc::invalid_length);
        }
        if(dst.size() > 255)
        {
            return result<validated_g2_affine_le>::failure(bls_errc::invalid_length);
        }

        std::array<uint8_t, 4 * 64> expanded{};
        xmd_sh256(
            expanded.data(),
            static_cast<int>(expanded.size()),
            message.data(),
            static_cast<int>(message.size()),
            reinterpret_cast<const uint8_t*>(dst.data()),
            static_cast<int>(dst.size())
        );

        std::array<eosio::bls_fp, 4> field_elements{};
        for(size_t i = 0; i < field_elements.size(); ++i)
        {
            std::array<uint8_t, 64> chunk{};
            memcpy(chunk.data(), expanded.data() + i * chunk.size(), chunk.size());
            const std::array<uint64_t, 8> scalar = longScalarFromBytesBE(chunk);

            eosio::bls_s wide_scalar{};
            memcpy(wide_scalar.data(), scalar.data(), wide_scalar.size());
            const auto reduced = host_detail::fp_mod(wide_scalar);
            if(!reduced)
            {
                return result<validated_g2_affine_le>::failure(
                    bls_errc::host_operation_failed,
                    reduced.error().host_status
                );
            }
            field_elements[i] = reduced.value();
        }

        eosio::bls_fp2 first_field{};
        first_field[0] = field_elements[0];
        first_field[1] = field_elements[1];
        const auto first_point = host_detail::g2_map(first_field);
        if(!first_point)
        {
            return result<validated_g2_affine_le>::failure(
                bls_errc::host_operation_failed,
                first_point.error().host_status
            );
        }

        eosio::bls_fp2 second_field{};
        second_field[0] = field_elements[2];
        second_field[1] = field_elements[3];
        const auto second_point = host_detail::g2_map(second_field);
        if(!second_point)
        {
            return result<validated_g2_affine_le>::failure(
                bls_errc::host_operation_failed,
                second_point.error().host_status
            );
        }

        const auto sum = host_detail::g2_add(first_point.value(), second_point.value());
        if(!sum)
        {
            return result<validated_g2_affine_le>::failure(
                bls_errc::host_operation_failed,
                sum.error().host_status
            );
        }

        g2 point;
        memcpy(point.data(), sum.value().data(), sizeof(g2));
        if(point.isIdentity())
        {
            return result<validated_g2_affine_le>::failure(bls_errc::identity_point);
        }

        // Both map operations clear the G2 cofactor in the authoritative host
        // implementation. Their sum therefore remains in the prime-order subgroup.
        return result<validated_g2_affine_le>::success(
            validated_g2_affine_le::from_trusted_point(point)
        );
    }

    inline result<validated_g2_affine_le> hash_to_g2(
        const std::span<const uint8_t> message,
        const signature_suite suite
    )
    {
        return hash_to_g2(message, ciphersuite_dst(suite));
    }

    inline g2 fromMessage(const std::vector<uint8_t>& msg, const std::string& dst)
    {
        auto hashed = hash_to_g2(std::span<const uint8_t>(msg.data(), msg.size()), std::string_view(dst));
        eosio::check(hashed.has_value(), "fromMessage: hash_to_g2 failed");
        return hashed.value().point();
    }

    inline result<validated_g1_affine_le> aggregate_public_keys(
        const std::span<const validated_g1_affine_le> keys
    )
    {
        if(keys.empty())
        {
            return result<validated_g1_affine_le>::failure(bls_errc::empty_input);
        }
        if(!host_detail::valid_count_for_host(keys.size(), sizeof(eosio::bls_g1)) ||
           !host_detail::valid_count_for_host(keys.size(), sizeof(eosio::bls_scalar)))
        {
            return result<validated_g1_affine_le>::failure(bls_errc::count_overflow);
        }

        std::vector<eosio::bls_g1> host_keys(keys.size());
        std::vector<eosio::bls_scalar> coefficients(keys.size());
        const scalar one(1, 0, 0, 0);
        for(size_t i = 0; i < keys.size(); ++i)
        {
            memcpy(host_keys[i].data(), keys[i].point().data(), host_keys[i].size());
            memcpy(coefficients[i].data(), one.data(), coefficients[i].size());
        }

        const auto sum = host_detail::g1_weighted_sum(host_keys.data(), coefficients.data(), keys.size());
        if(!sum)
        {
            return result<validated_g1_affine_le>::failure(
                bls_errc::host_operation_failed,
                sum.error().host_status
            );
        }

        g1 aggregate;
        memcpy(aggregate.data(), sum.value().data(), sizeof(g1));
        if(aggregate.isIdentity())
        {
            return result<validated_g1_affine_le>::failure(bls_errc::identity_point);
        }

        return result<validated_g1_affine_le>::success(
            validated_g1_affine_le::from_trusted_point(aggregate)
        );
    }

    inline result<signature_verdict> verify_basic_g2_signature(
        const validated_g1_affine_le& public_key,
        const std::span<const uint8_t> message,
        const validated_g2_affine_le& signature
    )
    {
        const auto hashed_message = hash_to_g2(message, signature_suite::basic);
        if(!hashed_message)
        {
            return result<signature_verdict>::failure(
                hashed_message.error().code,
                hashed_message.error().host_status
            );
        }

        std::array<eosio::bls_g1, 2> g1_points{};
        std::array<eosio::bls_g2, 2> g2_points{};
        memcpy(g1_points[0].data(), g1::BASE_NEG.data(), g1_points[0].size());
        memcpy(g2_points[0].data(), signature.point().data(), g2_points[0].size());
        memcpy(g1_points[1].data(), public_key.point().data(), g1_points[1].size());
        memcpy(g2_points[1].data(), hashed_message.value().point().data(), g2_points[1].size());

        const auto pairing_result = host_detail::pairing(g1_points.data(), g2_points.data(), g1_points.size());
        if(!pairing_result)
        {
            return result<signature_verdict>::failure(
                bls_errc::host_operation_failed,
                pairing_result.error().host_status
            );
        }

        fp12 product;
        memcpy(product.data(), pairing_result.value().data(), sizeof(fp12));
        return result<signature_verdict>::success(
            product.equal(fp12::one()) ? signature_verdict::valid : signature_verdict::invalid
        );
    }

    inline bool equal_binary_messages(const binary_message_view lhs, const binary_message_view rhs)
    {
        return lhs.size() == rhs.size() && std::equal(lhs.begin(), lhs.end(), rhs.begin());
    }

    inline result<signature_verdict> aggregate_verify_basic(
        const std::span<const validated_g1_affine_le> grouped_public_keys,
        const std::span<const binary_message_view> messages,
        const validated_g2_affine_le& aggregate_signature
    )
    {
        if(grouped_public_keys.empty())
        {
            return result<signature_verdict>::failure(bls_errc::empty_input);
        }
        if(grouped_public_keys.size() != messages.size())
        {
            return result<signature_verdict>::failure(bls_errc::length_mismatch);
        }
        if(grouped_public_keys.size() >= std::numeric_limits<uint32_t>::max())
        {
            return result<signature_verdict>::failure(bls_errc::count_overflow);
        }

        for(size_t i = 0; i < messages.size(); ++i)
        {
            for(size_t j = i + 1; j < messages.size(); ++j)
            {
                if(equal_binary_messages(messages[i], messages[j]))
                {
                    return result<signature_verdict>::failure(bls_errc::duplicate_message);
                }
            }
        }

        const size_t pairing_count = grouped_public_keys.size() + 1;
        if(!host_detail::valid_count_for_host(pairing_count, sizeof(eosio::bls_g1)) ||
           !host_detail::valid_count_for_host(pairing_count, sizeof(eosio::bls_g2)))
        {
            return result<signature_verdict>::failure(bls_errc::count_overflow);
        }

        std::vector<eosio::bls_g1> g1_points(pairing_count);
        std::vector<eosio::bls_g2> g2_points(pairing_count);
        memcpy(g1_points[0].data(), g1::BASE_NEG.data(), g1_points[0].size());
        memcpy(g2_points[0].data(), aggregate_signature.point().data(), g2_points[0].size());

        for(size_t i = 0; i < grouped_public_keys.size(); ++i)
        {
            const auto hashed_message = hash_to_g2(messages[i], signature_suite::basic);
            if(!hashed_message)
            {
                return result<signature_verdict>::failure(
                    hashed_message.error().code,
                    hashed_message.error().host_status
                );
            }
            memcpy(g1_points[i + 1].data(), grouped_public_keys[i].point().data(), g1_points[i + 1].size());
            memcpy(g2_points[i + 1].data(), hashed_message.value().point().data(), g2_points[i + 1].size());
        }

        const auto pairing_result = host_detail::pairing(g1_points.data(), g2_points.data(), pairing_count);
        if(!pairing_result)
        {
            return result<signature_verdict>::failure(
                bls_errc::host_operation_failed,
                pairing_result.error().host_status
            );
        }

        fp12 product;
        memcpy(product.data(), pairing_result.value().data(), sizeof(fp12));
        return result<signature_verdict>::success(
            product.equal(fp12::one()) ? signature_verdict::valid : signature_verdict::invalid
        );
    }

    namespace groth16
    {
        class Proof
        {
            public:
            g1 a;
            g2 b;
            g1 c;
            EOSLIB_SERIALIZE(Proof, (a)(b)(c))

            Proof() : a(g1()), b(g2()), c(g1()) {}
            Proof(const g1& a, const g2& b, const g1& c) : a(a), b(b), c(c) {}
            Proof(const Proof& proof) : a(proof.a), b(proof.b), c(proof.c) {}
            static Proof fromAffineBytesLE(const std::span<const uint8_t, 384> in)
            {
                g1 a = g1::fromAffineBytesLE(std::span<const uint8_t,  96>(&in[  0], &in[ 96]));
                g2 b = g2::fromAffineBytesLE(std::span<const uint8_t, 192>(&in[ 96], &in[288]));
                g1 c = g1::fromAffineBytesLE(std::span<const uint8_t,  96>(&in[288], &in[384]));
                return Proof(a, b, c);
            }
        };

        class VerifyingKey
        {
            public:
            g1 alpha_g1;        // alpha in g1 for verifying and for creating A/C elements of proof. Never the point at infinity.
            g1 beta_g1;         // beta in g1 and g2 for verifying and for creating B/C elements of proof. Never the point at infinity.
            g2 beta_g2;
            g2 gamma_g2;        // gamma in g2 for verifying. Never the point at infinity.
            g1 delta_g1;        // delta in g1/g2 for verifying and proving, essentially the magic trapdoor that forces the prover to
            g2 delta_g2;        // evaluate the C element of the proof with only components from the CRS. Never the point at infinity.
            std::vector<g1> ic; // Elements of the form (beta * u_i(tau) + alpha v_i(tau) + w_i(tau)) / gamma for all public inputs.
                                // Because all public inputs have a dummy constraint, this is the same size as the number of inputs,
                                // and never contains points at infinity.
            EOSLIB_SERIALIZE(VerifyingKey, (alpha_g1)(beta_g1)(beta_g2)(gamma_g2)(delta_g1)(delta_g2)(ic))

            VerifyingKey() : alpha_g1(g1()), beta_g1(g1()), beta_g2(g2()), gamma_g2(g2()), delta_g1(g1()), delta_g2(g2()), ic(std::vector<g1>()) {}
            VerifyingKey(
                const g1& alpha_g1,
                const g1& beta_g1,
                const g2& beta_g2,
                const g2& gamma_g2,
                const g1& delta_g1,
                const g2& delta_g2,
                const std::vector<g1>& ic
            ) : alpha_g1(alpha_g1), beta_g1(beta_g1), beta_g2(beta_g2), gamma_g2(gamma_g2), delta_g1(delta_g1), delta_g2(delta_g2), ic(ic) {}
            VerifyingKey(const VerifyingKey& vk)
                : alpha_g1(vk.alpha_g1), beta_g1(vk.beta_g1), beta_g2(vk.beta_g2), gamma_g2(vk.gamma_g2), delta_g1(vk.delta_g1), delta_g2(vk.delta_g2), ic(vk.ic) {}
            static VerifyingKey fromAffineBytesLE(const uint8_t* in)
            {
                g1 alpha_g1 = g1::fromAffineBytesLE(std::span<const uint8_t,  96>(&in[  0], &in[ 96]));
                g1 beta_g1 =  g1::fromAffineBytesLE(std::span<const uint8_t,  96>(&in[ 96], &in[192]));
                g2 beta_g2 =  g2::fromAffineBytesLE(std::span<const uint8_t, 192>(&in[192], &in[384]));
                g2 gamma_g2 = g2::fromAffineBytesLE(std::span<const uint8_t, 192>(&in[384], &in[576]));
                g1 delta_g1 = g1::fromAffineBytesLE(std::span<const uint8_t,  96>(&in[576], &in[672]));
                g2 delta_g2 = g2::fromAffineBytesLE(std::span<const uint8_t, 192>(&in[672], &in[864]));
                std::vector<g1> ic;
                uint32_t n_ic = bls12_381_cdt_detail::readUint32LE(in + 864);
                ic.reserve(n_ic);
                for(uint32_t i = 0; i < n_ic; i++)
                {
                    ic.push_back(g1::fromAffineBytesLE(std::span<const uint8_t, 96>(&in[868 + i*96], &in[868 + (i+1)*96])));
                }
                return VerifyingKey(
                    alpha_g1,
                    beta_g1,
                    beta_g2,
                    gamma_g2,
                    delta_g1,
                    delta_g2,
                    ic
                );
            }
            static VerifyingKey fromAffineBytesLE(const std::vector<uint8_t>& in)
            {
                constexpr size_t prefix_size = 868;
                constexpr size_t ic_element_size = 96;
                eosio::check(in.size() >= prefix_size, "VerifyingKey::fromAffineBytesLE: input is too short");
                const uint32_t n_ic = bls12_381_cdt_detail::readUint32LE(in.data() + 864);
                const size_t expected_size = bls12_381_cdt_detail::encodedVectorSize(prefix_size, n_ic, ic_element_size);
                eosio::check(in.size() >= expected_size, "VerifyingKey::fromAffineBytesLE: truncated IC vector");
                return fromAffineBytesLE(in.data());
            }
        };

        class PreparedVerifyingKey
        {
            public:
            fp12 alpha_g1_beta_g2;      // Pairing result of alpha*beta
            g2 neg_gamma_g2;            // -gamma in G2
            g2 neg_delta_g2;            // -delta in G2
            std::vector<g1> ic;         // Copy of 'ic' from `vk`
            EOSLIB_SERIALIZE(PreparedVerifyingKey, (alpha_g1_beta_g2)(neg_gamma_g2)(neg_delta_g2)(ic))

            PreparedVerifyingKey() : alpha_g1_beta_g2(fp12()), neg_gamma_g2(g2()), neg_delta_g2(g2()), ic(std::vector<g1>()) {}
            PreparedVerifyingKey(const fp12& alpha_g1_beta_g2, const g2& neg_gamma_g2, const g2& neg_delta_g2, const std::vector<g1>& ic) :
                alpha_g1_beta_g2(alpha_g1_beta_g2), neg_gamma_g2(neg_gamma_g2), neg_delta_g2(neg_delta_g2), ic(ic) {}
            PreparedVerifyingKey(const PreparedVerifyingKey& pvk) :
                alpha_g1_beta_g2(pvk.alpha_g1_beta_g2), neg_gamma_g2(pvk.neg_gamma_g2), neg_delta_g2(pvk.neg_delta_g2), ic(pvk.ic) {}
            static PreparedVerifyingKey fromAffineBytesLE(const uint8_t* in)
            {
                fp12 alpha_g1_beta_g2 = fp12::fromBytesLE(std::span<const uint8_t, 576>(&in[  0], &in[576]));
                g2 neg_gamma_g2 =   g2::fromAffineBytesLE(std::span<const uint8_t, 192>(&in[576], &in[768]));
                g2 neg_delta_g2 =   g2::fromAffineBytesLE(std::span<const uint8_t, 192>(&in[768], &in[960]));
                std::vector<g1> ic;
                uint32_t n_ic = bls12_381_cdt_detail::readUint32LE(in + 960);
                ic.reserve(n_ic);
                for(uint32_t i = 0; i < n_ic; i++)
                {
                    ic.push_back(g1::fromAffineBytesLE(std::span<const uint8_t, 96>(&in[964 + i*96], &in[964 + (i+1)*96])));
                }
                return PreparedVerifyingKey(
                    alpha_g1_beta_g2,
                    neg_gamma_g2,
                    neg_delta_g2,
                    ic
                );
            }
            static PreparedVerifyingKey fromAffineBytesLE(const std::vector<uint8_t>& in)
            {
                constexpr size_t prefix_size = 964;
                constexpr size_t ic_element_size = 96;
                eosio::check(in.size() >= prefix_size, "PreparedVerifyingKey::fromAffineBytesLE: input is too short");
                const uint32_t n_ic = bls12_381_cdt_detail::readUint32LE(in.data() + 960);
                const size_t expected_size = bls12_381_cdt_detail::encodedVectorSize(prefix_size, n_ic, ic_element_size);
                eosio::check(in.size() >= expected_size, "PreparedVerifyingKey::fromAffineBytesLE: truncated IC vector");
                return fromAffineBytesLE(in.data());
            }
        };

        inline PreparedVerifyingKey prepare_verifying_key(const VerifyingKey& vk)
        {
            return PreparedVerifyingKey(
                pairing::calculate(&vk.alpha_g1, &vk.beta_g2, 1),
                vk.gamma_g2.neg(),
                vk.delta_g2.neg(),
                vk.ic
            );
        }

        // public_inputs must contain one scalar for every pvk.ic element.
        // The conventional implicit Groth16 constant is not inserted here: callers
        // must provide scalar(1, 0, 0, 0) as public_inputs[0], followed by the actual
        // public inputs in the verifying key's expected order.
        inline bool verify_proof(
            const PreparedVerifyingKey& pvk,
            const Proof& proof,
            const std::vector<scalar>& public_inputs
        )
        {
            if(public_inputs.size() != pvk.ic.size())
            {
                return false;
            }
            g1 acc = g1::multiExp(pvk.ic.data(), public_inputs.data(), pvk.ic.size());
            std::vector<g1> g1_points; g1_points.reserve(3);
            std::vector<g2> g2_points; g2_points.reserve(3);
            g1_points.push_back(proof.a);   g2_points.push_back(proof.b);
            g1_points.push_back(acc);       g2_points.push_back(pvk.neg_gamma_g2);
            g1_points.push_back(proof.c);   g2_points.push_back(pvk.neg_delta_g2);
            return pvk.alpha_g1_beta_g2.equal(pairing::calculate(g1_points.data(), g2_points.data(), 3));
        };
    } // namespace groth16

    // the following compile-time assertions guarantee that all type casts as implemented
    // above (i.e. between std::array types, eosio types and bls12_381 types) are valid
    // source: https://stackoverflow.com/a/69500849/2340535
    static_assert(sizeof(scalar) == sizeof(uint64_t[4]));
    static_assert(sizeof(scalar) == sizeof(std::array<uint64_t, 4>));
    static_assert(sizeof(scalar) == sizeof(eosio::bls_scalar));
    static_assert(sizeof(fp) == sizeof(uint64_t[6]));
    static_assert(sizeof(fp) == sizeof(std::array<uint64_t, 6>));
    static_assert(sizeof(fp) == sizeof(eosio::bls_fp));
    static_assert(sizeof(fp2) == sizeof(fp[2]));
    static_assert(sizeof(fp2) == sizeof(std::array<fp, 2>));
    static_assert(sizeof(fp2) == sizeof(eosio::bls_fp2));
    static_assert(sizeof(fp6) == sizeof(fp2[3]));
    static_assert(sizeof(fp6) == sizeof(std::array<fp2, 3>));
    static_assert(sizeof(fp12) == sizeof(fp6[2]));
    static_assert(sizeof(fp12) == sizeof(std::array<fp6, 2>));
    static_assert(sizeof(fp12) == sizeof(eosio::bls_gt));
    static_assert(sizeof(std::array<uint64_t, 8>) == sizeof(eosio::bls_s));
    static_assert(sizeof(uint64_t[8]) == sizeof(eosio::bls_s));
} // namespace bls12_381

namespace jubjub
{
    class AffineNielsPoint
    {
        public:
        bls12_381::scalar v_plus_u;
        bls12_381::scalar v_minus_u;
        bls12_381::scalar t2d;

        AffineNielsPoint() : v_plus_u(bls12_381::scalar()), v_minus_u(bls12_381::scalar()), t2d(bls12_381::scalar()) {}
        AffineNielsPoint(const bls12_381::scalar& u, const bls12_381::scalar& v) : v_plus_u(v.add(u)), v_minus_u(v.sub(u)), t2d(u.mul(v).mul(bls12_381::scalar::EDWARDS_D2)) {} // from affine point (u, v)
    };

    class ExtendedPoint
    {
        public:
        bls12_381::scalar u;
        bls12_381::scalar v;
        bls12_381::scalar z;
        bls12_381::scalar t1;
        bls12_381::scalar t2;

        ExtendedPoint() : u(bls12_381::scalar()), v(bls12_381::scalar()), z(bls12_381::scalar()), t1(bls12_381::scalar()), t2(bls12_381::scalar()) {}
        ExtendedPoint(const bls12_381::scalar& u, const bls12_381::scalar& v, const bls12_381::scalar& z, const bls12_381::scalar& t1, const bls12_381::scalar& t2) : u(u), v(v), z(z), t1(t1), t2(t2) {}
        ExtendedPoint(const bls12_381::scalar& u, const bls12_381::scalar& v) : u(u), v(v), z(bls12_381::scalar::one()), t1(u), t2(v) {} // from affine point (u, v)

        ExtendedPoint add(const AffineNielsPoint& rhs) const
        {
            // This is identical to the addition formula for `ExtendedNielsPoint`,
            // except we can assume that `rhs.z` is one, so that we perform
            // 7 multiplications.
            bls12_381::scalar a = v.sub(u).mul(rhs.v_minus_u);
            bls12_381::scalar b = v.add(u).mul(rhs.v_plus_u);
            bls12_381::scalar c = t1.mul(t2).mul(rhs.t2d);
            bls12_381::scalar d = z.add(z);

            // The remaining arithmetic is exactly the process of converting
            // from a completed point to an extended point.
            bls12_381::scalar cp_u = b.sub(a);
            bls12_381::scalar cp_v = b.add(a);
            bls12_381::scalar cp_z = d.add(c);
            bls12_381::scalar cp_t = d.sub(c);

            return ExtendedPoint(
                cp_u.mul(cp_t),
                cp_v.mul(cp_z),
                cp_z.mul(cp_t),
                cp_u,
                cp_v
            );
        }

        inline bool equal(const ExtendedPoint& rhs) const
        {
            // (u/z, v/z) = (u'/z', v'/z') is implied by
            //      (uz'z = u'z'z) and
            //      (vz'z = v'z'z)
            // as z and z' are always nonzero.
            return u.mul(rhs.z).equal(rhs.u.mul(z)) && v.mul(rhs.z).equal(rhs.v.mul(z));
        }
    };
}
