#include <eosio/eosio.hpp>
#include <eosio/crypto_bls_ext.hpp>
#include <span>

#include "sha256.hpp"

template<size_t N>
std::string bytesToHex(const std::span<const uint8_t, N>& in)
{
    constexpr char hexmap[] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
    std::string s(2 + N * 2, ' ');
    s[0] = '0';
    s[1] = 'x';
    for(uint64_t i = 0; i < N; i++)
    {
        s[2 + 2*i]     = hexmap[(in[i] & 0xF0) >> 4];
        s[2 + 2*i+1]   = hexmap[ in[i] & 0x0F      ];
    }
    return s;
}
std::string bytesToHex(const std::vector<uint8_t>& in)
{
    constexpr char hexmap[] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
    std::string s(2 + in.size() * 2, ' ');
    s[0] = '0';
    s[1] = 'x';
    for(uint64_t i = 0; i < in.size(); ++i)
    {
        s[2 + 2*i]     = hexmap[(in[i] & 0xF0) >> 4];
        s[2 + 2*i+1]   = hexmap[ in[i] & 0x0F      ];
    }
    return s;
}
template<size_t N>
void hexToBytes(const std::string& s, std::span<uint8_t, N> out)
{
    // No checks on the string length in the compile time version!
    uint64_t start_idx = 0;
    if(s[0] == '0' && s[1] == 'x')
    {
        start_idx = 2;
    }

    for(size_t i = 0, j = start_idx; i < N; i++, j += 2)
    {
        out[i] = (s[j] % 32 + 9) % 25 * 16 + (s[j+1] % 32 + 9) % 25;
    }
}
template<size_t N>
std::array<uint8_t, N> hexToBytes(const std::string& s)
{
    std::array<uint8_t, N> out;
    hexToBytes<N>(s, out);
    return out;
}
std::vector<uint8_t> hexToBytes(const std::string& s)
{
    uint64_t start_idx = 0;
    if(s[0] == '0' && s[1] == 'x')
    {
        start_idx = 2;
    }

    if(s.length() % 2 != 0)
    {
        //throw invalid_argument("string length invalid!");
        return std::vector<uint8_t>();
    }

    std::vector<uint8_t> bytes;
    uint64_t num_bytes = (s.length() - start_idx) / 2;
    bytes.reserve(num_bytes);
    for(size_t i = 0, j = start_idx; i < num_bytes; i++, j += 2)
    {
        bytes.push_back((s[j] % 32 + 9) % 25 * 16 + (s[j+1] % 32 + 9) % 25);
    }

    return bytes;
}

namespace bls12_381
{
    std::tuple<uint64_t, uint64_t> Sub64(
        const uint64_t& x,
        const uint64_t& y,
        const uint64_t& borrow
    )
    {
        uint64_t diff = x - y - borrow;
        uint64_t borrowOut = (diff > x);
        return {diff, borrowOut};
    }
    std::array<uint64_t, 8> longScalarFromBytesBE(const std::array<uint8_t, 8*8>& in)
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
            return *reinterpret_cast<uint64_t*>(&this->w0 + i * sizeof(uint64_t));
        }
        static scalar fromBytesLE(const std::span<const uint8_t, 4 * sizeof(uint64_t)>& in)
        {
            scalar out;
            memcpy(out.data(), in.data(), 4 * sizeof(uint64_t));
            return out;
        }
        bool equal(const scalar& e) const
        {
            return w0 == e.w0 && w1 == e.w1 && w2 == e.w2 && w3 == e.w3;
        }

        static const scalar Q;
    };
    const scalar scalar::Q = {
        0xffff'ffff'0000'0001,
        0x53bd'a402'fffe'5bfe,
        0x3339'd808'09a1'd805,
        0x73ed'a753'299d'7d48
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
            return *reinterpret_cast<uint64_t*>(&this->w0 + i * sizeof(uint64_t));
        }
        static fp fromRawBytesLE(const std::span<const uint8_t, 6 * sizeof(uint64_t)>& in)
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
            uint64_t borrow, _;
            std::tie(z.w0, borrow) = Sub64(fp::MODULUS.w0, this->w0, 0);
            std::tie(z.w1, borrow) = Sub64(fp::MODULUS.w1, this->w1, borrow);
            std::tie(z.w2, borrow) = Sub64(fp::MODULUS.w2, this->w2, borrow);
            std::tie(z.w3, borrow) = Sub64(fp::MODULUS.w3, this->w3, borrow);
            std::tie(z.w4, borrow) = Sub64(fp::MODULUS.w4, this->w4, borrow);
            std::tie(z.w5, _)      = Sub64(fp::MODULUS.w5, this->w5, borrow);
            return z;
        }
        static fp modPrime(const std::array<uint64_t, 8>& k)
        {
            fp out;
            eosio::bls_fp_mod(reinterpret_cast<const uint8_t*>(k.data()), out);
            return out;
        }

        static const fp MODULUS;
        static const fp R1;
    };
    const fp fp::MODULUS = fp(
        0xb9fe'ffff'ffff'aaab,
        0x1eab'fffe'b153'ffff,
        0x6730'd2a0'f6b0'f624,
        0x6477'4b84'f385'12bf,
        0x4b1b'a7b6'434b'acd7,
        0x1a01'11ea'397f'e69a
    );
    const fp fp::R1 = fp(
        0x7609'0000'0002'fffd,
        0xebf4'000b'c40c'0002,
        0x5f48'9857'53c7'58ba,
        0x77ce'5853'7052'5745,
        0x5c07'1a97'a256'ec6d,
        0x15f6'5ec3'fa80'e493
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
        static fp2 fromRawBytesLE(const std::span<const uint8_t, 2 * sizeof(fp)>& in)
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
        static fp6 fromRawBytesLE(const std::span<const uint8_t, 3 * sizeof(fp2)>& in)
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
        static fp12 fromRawBytesLE(const std::span<const uint8_t, 2 * sizeof(fp6)>& in)
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

    class g1
    {
        public:
        fp x;
        fp y;
        fp z;
        EOSLIB_SERIALIZE(g1, (x)(y)(z))

        g1() : x(fp()), y(fp()), z(fp()) {}
        g1(const fp& x, const fp& y, const fp& z) : x(x), y(y), z(z) {}
        g1(const std::array<fp, 3>& d) : x(d[0]), y(d[1]), z(d[2]) {}
        g1(const g1& e) : x(e.x), y(e.y), z(e.z) {}
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
        static g1 fromRawJacobianBytesLE(const std::span<const uint8_t, 3 * sizeof(fp)> in)
        {
            fp x = fp::fromRawBytesLE(std::span<const uint8_t, sizeof(fp)>(&in[ 0], &in[ 48]));
            fp y = fp::fromRawBytesLE(std::span<const uint8_t, sizeof(fp)>(&in[48], &in[ 96]));
            fp z = fp::fromRawBytesLE(std::span<const uint8_t, sizeof(fp)>(&in[96], &in[144]));
            g1 p = g1(x, y, z);
            return p;
        }
        static g1 fromRawAffineBytesLE(const std::span<const uint8_t, 2 * sizeof(fp)> in)
        {
            fp x = fp::fromRawBytesLE(std::span<const uint8_t, sizeof(fp)>(&in[ 0], &in[ 48]));
            fp y = fp::fromRawBytesLE(std::span<const uint8_t, sizeof(fp)>(&in[48], &in[ 96]));
            // check if given input points to infinity
            if(x.isZero() && y.isZero())
            {
                return zero();
            }
            fp z = fp::one();
            g1 p = g1(x, y, z);
            return p;
        }
        static g1 zero()
        {
            return g1(
                fp::zero(),
                fp::one(),
                fp::zero()
            );
        }
        static g1 one()
        {
            return BASE;
        }
        bool isZero() const
        {
            return z.isZero();
        }
        bool inCorrectSubgroup() const
        {
            return mulScalar(scalar::Q).isZero();
        }
        bool isAffine() const
        {
            return z.isOne();
        }
        g1 add(const g1& e) const
        {
            if(isZero())
            {
                return e;
            }
            if(e.isZero())
            {
                return *this;
            }
            g1 out;
            eosio::bls_g1_add(*this, e, out);
            return out;
        }
        g1 dbl() const
        {
            return this->add(*this);
        }
        g1 neg() const
        {
            g1 r;
            r.x = x;
            r.y = y.neg();
            r.z = z;
            return r;
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
            eosio::bls_g1_mul(*this, s, out);
            return out;
        }
        static g1 multiExp(const std::vector<g1>& points, const std::vector<scalar>& scalars)
        {
            eosio::check(points.size() == scalars.size(), "g1 multiExp: points and scalars must have same number of elements");
            g1 out;
            const eosio::bls_g1* p = reinterpret_cast<const eosio::bls_g1*>(points.data());
            const eosio::bls_scalar* s = reinterpret_cast<const eosio::bls_scalar*>(scalars.data());
            eosio::bls_g1_exp(p, s, points.size(), out);
            return out;
        }
        static g1 mapToCurve(const fp& e)
        {
            g1 out;
            eosio::bls_g1_map(e, out);
            return out;
        }

        static const g1 BASE;
        static const scalar cofactorEFF;
    };
    const g1 g1::BASE = g1(
        fp(0x5cb38790fd530c16, 0x7817fc679976fff5, 0x154f95c7143ba1c1, 0xf0ae6acdf3d0e747, 0xedce6ecc21dbf440, 0x120177419e0bfb75),
        fp(0xbaac93d50ce72271, 0x8c22631a7918fd8e, 0xdd595f13570725ce, 0x51ac582950405194, 0x0e1c8c3fad0059c0, 0x0bbc3efc5008a26a),
        fp(0x760900000002fffd, 0xebf4000bc40c0002, 0x5f48985753c758ba, 0x77ce585370525745, 0x5c071a97a256ec6d, 0x15f65ec3fa80e493)
    );
    const scalar g1::cofactorEFF = {0xd201000000010001, 0, 0, 0};

    class g2
    {
        public:
        fp2 x;
        fp2 y;
        fp2 z;
        EOSLIB_SERIALIZE(g2, (x)(y)(z))

        g2() : x(fp2()), y(fp2()), z(fp2()) {}
        g2(const fp2& x, const fp2& y, const fp2& z) : x(x), y(y), z(z) {}
        g2(const std::array<fp2, 3>& d) : x(d[0]), y(d[1]), z(d[2]) {}
        g2(const g2& e) : x(e.x), y(e.y), z(e.z) {}
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
        static g2 fromRawJacobianBytesLE(const std::span<const uint8_t, 3 * sizeof(fp2)> in)
        {
            fp2 x = fp2::fromRawBytesLE(std::span<const uint8_t, sizeof(fp2)>(&in[  0], &in[ 96]));
            fp2 y = fp2::fromRawBytesLE(std::span<const uint8_t, sizeof(fp2)>(&in[ 96], &in[192]));
            fp2 z = fp2::fromRawBytesLE(std::span<const uint8_t, sizeof(fp2)>(&in[192], &in[288]));
            g2 p = g2(x, y, z);
            return p;
        }
        static g2 fromRawAffineBytesLE(const std::span<const uint8_t, 2 * sizeof(fp2)> in)
        {
            fp2 x = fp2::fromRawBytesLE(std::span<const uint8_t, sizeof(fp2)>(&in[ 0], &in[ 96]));
            fp2 y = fp2::fromRawBytesLE(std::span<const uint8_t, sizeof(fp2)>(&in[96], &in[192]));
            // check if given input points to infinity
            if(x.isZero() && y.isZero())
            {
                return zero();
            }
            fp2 z = fp2::one();
            g2 p = g2(x, y, z);
            return p;
        }
        static g2 zero()
        {
            return g2(
                fp2::zero(),
                fp2::one(),
                fp2::zero()
            );
        }
        g2 one()
        {
            return BASE;
        }
        bool isZero() const
        {
            return z.isZero();
        }
        bool inCorrectSubgroup() const
        {
            return mulScalar(scalar::Q).isZero();
        }
        bool isAffine() const
        {
            return z.isOne();
        }
        g2 add(const g2& e) const
        {
            if(isZero())
            {
                return e;
            }
            if(e.isZero())
            {
                return *this;
            }
            g2 out;
            eosio::bls_g2_add(*this, e, out);
            return out;
        }
        g2 dbl() const
        {
            return this->add(*this);
        }
        g2 neg() const
        {
            return g2(x, y.neg(), z);
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
            eosio::bls_g2_mul(*this, s, out);
            return out;
        }
        static g2 multiExp(const std::vector<g2>& points, const std::vector<scalar>& scalars)
        {
            eosio::check(points.size() == scalars.size(), "g2 multiExp: points and scalars must have same number of elements");
            g2 out;
            const eosio::bls_g2* p = reinterpret_cast<const eosio::bls_g2*>(points.data());
            const eosio::bls_scalar* s = reinterpret_cast<const eosio::bls_scalar*>(scalars.data());
            eosio::bls_g2_exp(p, s, points.size(), out);
            return out;
        }
        static g2 mapToCurve(const fp2& e)
        {
            g2 out;
            eosio::bls_g2_map(e, out);
            return out;
        }

        static const g2 BASE;
    };
    const g2 g2::BASE = g2(
        fp2(
            fp(0xf5f28fa202940a10, 0xb3f5fb2687b4961a, 0xa1a893b53e2ae580, 0x9894999d1a3caee9, 0x6f67b7631863366b, 0x058191924350bcd7),
            fp(0xa5a9c0759e23f606, 0xaaa0c59dbccd60c3, 0x3bb17e18e2867806, 0x1b1ab6cc8541b367, 0xc2b6ed0ef2158547, 0x11922a097360edf3)
        ),
        fp2(
            fp(0x4c730af860494c4a, 0x597cfa1f5e369c5a, 0xe7e6856caa0a635a, 0xbbefb5e96e0d495f, 0x07d3a975f0ef25a2, 0x083fd8e7e80dae5),
            fp(0xadc0fc92df64b05d, 0x18aa270a2b1461dc, 0x86adac6a3be4eba0, 0x79495c4ec93da33a, 0xe7175850a43ccaed, 0xb2bc2a163de1bf2)
        ),
        fp2(
            fp(0x760900000002fffd, 0xebf4000bc40c0002, 0x5f48985753c758ba, 0x77ce585370525745, 0x5c071a97a256ec6d, 0x15f65ec3fa80e493),
            fp(0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000)
        )
    );

    namespace pairing
    {
        fp12 calculate(std::vector<g1>& g1_points, std::vector<g2>& g2_points)
        {
            eosio::check(g1_points.size() == g2_points.size(), "pairing: g1_points and g2_points must have same number of elements");
            fp12 f;
            const eosio::bls_g1* p1 = reinterpret_cast<const eosio::bls_g1*>(g1_points.data());
            const eosio::bls_g2* p2 = reinterpret_cast<const eosio::bls_g2*>(g2_points.data());
            eosio::bls_pairing(p1, p2, g1_points.size(), f);
            return f;
        }
    }

    // signatures.cpp functions
    
    // Construct an extensible-output function based on SHA256
    void xmd_sh256(
        uint8_t *buf,
        int buf_len,
        const uint8_t *in,
        int in_len,
        const uint8_t *dst,
        int dst_len
    )
    {
        const unsigned int SHA256HashSize = 32;
        const unsigned int SHA256_Message_Block_Size = 64;
        const unsigned ell = (buf_len + SHA256HashSize - 1) / SHA256HashSize;
        if (buf_len < 0 || ell > 255 || dst_len > 255)
        {
            return;
        }
        const uint8_t Z_pad[SHA256_Message_Block_Size] = { 0, };
        const uint8_t l_i_b_0_str[] = {
            static_cast<uint8_t>(buf_len >> 8),
            static_cast<uint8_t>(buf_len & 0xff),
            0,
            static_cast<uint8_t>(dst_len)
        };
        const uint8_t *dstlen_str = l_i_b_0_str + 3;
        uint8_t b_0[SHA256HashSize];
        sha256 sha;
        sha.update(Z_pad, SHA256_Message_Block_Size);
        sha.update(in, in_len);
        sha.update(l_i_b_0_str, 3);
        sha.update(dst, dst_len);
        sha.update(dstlen_str, 1);
        sha.digest(b_0);
        uint8_t b_i[SHA256HashSize + 1] = { 0, };
        for (unsigned i = 1; i <= ell; ++i)
        {
            for (unsigned j = 0; j < SHA256HashSize; ++j)
            {
                b_i[j] = b_0[j] ^ b_i[j];
            }
            b_i[SHA256HashSize] = i;
            sha256 s;
            s.update(b_i, SHA256HashSize + 1);
            s.update(dst, dst_len);
            s.update(dstlen_str, 1);
            s.digest(b_i);
            const int rem_after = buf_len - i * SHA256HashSize;
            const int copy_len = SHA256HashSize + (rem_after < 0 ? rem_after : 0);
            memcpy(buf + (i - 1) * SHA256HashSize, b_i, copy_len);
        }
    }

    g2 fromMessage(const std::vector<uint8_t>& msg, const std::string& dst)
    {
        uint8_t buf[4 * 64];
        xmd_sh256(buf, 4 * 64, msg.data(), msg.size(), reinterpret_cast<const uint8_t*>(dst.c_str()), dst.length());

        std::array<uint64_t, 8> k;
        fp2 t;
        g2 p, q, res;

        k = longScalarFromBytesBE(*reinterpret_cast<std::array<uint8_t, 64>*>(buf));
        eosio::bls_fp_mod(reinterpret_cast<uint8_t*>(&k[0]), t[0]);
        k = longScalarFromBytesBE(*reinterpret_cast<std::array<uint8_t, 64>*>(buf + 64));
        eosio::bls_fp_mod(reinterpret_cast<uint8_t*>(&k[0]), t[1]);

        eosio::bls_g2_map(t, p);

        k = longScalarFromBytesBE(*reinterpret_cast<std::array<uint8_t, 64>*>(buf + 2*64));
        eosio::bls_fp_mod(reinterpret_cast<uint8_t*>(&k[0]), t[0]);
        k = longScalarFromBytesBE(*reinterpret_cast<std::array<uint8_t, 64>*>(buf + 3*64));
        eosio::bls_fp_mod(reinterpret_cast<uint8_t*>(&k[0]), t[1]);

        eosio::bls_g2_map(t, q);
        eosio::bls_g2_add(p, q, res);

        return res;
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

            Proof() : a(g1::zero()), b(g2::zero()), c(g1::zero()) {}
            Proof(const g1& a, const g2& b, const g1& c) : a(a), b(b), c(c) {}
            Proof(const Proof& proof) : a(proof.a), b(proof.b), c(proof.c) {}
            static Proof fromRawJacobianBytesLE(const std::span<const uint8_t, 576> in)
            {
                g1 a = g1::fromRawJacobianBytesLE(std::span<const uint8_t, 144>(&in[  0], &in[144]));
                g2 b = g2::fromRawJacobianBytesLE(std::span<const uint8_t, 288>(&in[144], &in[432]));
                g1 c = g1::fromRawJacobianBytesLE(std::span<const uint8_t, 144>(&in[432], &in[576]));
                return Proof(a, b, c);
            }
            static Proof fromRawAffineBytesLE(const std::span<const uint8_t, 384> in)
            {
                g1 a = g1::fromRawAffineBytesLE(std::span<const uint8_t,  96>(&in[  0], &in[ 96]));
                g2 b = g2::fromRawAffineBytesLE(std::span<const uint8_t, 192>(&in[ 96], &in[288]));
                g1 c = g1::fromRawAffineBytesLE(std::span<const uint8_t,  96>(&in[288], &in[384]));
                return Proof(a, b, c);
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

            PreparedVerifyingKey() : alpha_g1_beta_g2(fp12::zero()), neg_gamma_g2(g2::zero()), neg_delta_g2(g2::zero()), ic(std::vector<g1>()) {}
            PreparedVerifyingKey(const fp12& alpha_g1_beta_g2, const g2& neg_gamma_g2, const g2& neg_delta_g2, const std::vector<g1>& ic) :
                alpha_g1_beta_g2(alpha_g1_beta_g2), neg_gamma_g2(neg_gamma_g2), neg_delta_g2(neg_delta_g2), ic(ic) {}
            PreparedVerifyingKey(const PreparedVerifyingKey& pvk) :
                alpha_g1_beta_g2(pvk.alpha_g1_beta_g2), neg_gamma_g2(pvk.neg_gamma_g2), neg_delta_g2(pvk.neg_delta_g2), ic(pvk.ic) {}
            static PreparedVerifyingKey fromRawJacobianBytesLE(const uint8_t* in)
            {
                fp12 alpha_g1_beta_g2 = fp12::fromRawBytesLE(std::span<const uint8_t, 576>(&in[   0], &in[ 576]));
                g2 neg_gamma_g2 = g2::fromRawJacobianBytesLE(std::span<const uint8_t, 288>(&in[ 576], &in[ 864]));
                g2 neg_delta_g2 = g2::fromRawJacobianBytesLE(std::span<const uint8_t, 288>(&in[ 864], &in[1152]));
                std::vector<g1> ic;
                uint32_t n_ic = in[1152] | in[1153] << 8 | in[1154] << 16 | in[1155] << 24;
                ic.reserve(n_ic);
                for(uint32_t i = 0; i < n_ic; i++)
                {
                    ic.push_back(g1::fromRawJacobianBytesLE(std::span<const uint8_t, 144>(&in[1156 + i*144], &in[1156 + (i+1)*144])));
                }
                return PreparedVerifyingKey(
                    alpha_g1_beta_g2,
                    neg_gamma_g2,
                    neg_delta_g2,
                    ic
                );
            }
            static PreparedVerifyingKey fromRawAffineBytesLE(const uint8_t* in)
            {
                fp12 alpha_g1_beta_g2 = fp12::fromRawBytesLE(std::span<const uint8_t, 576>(&in[  0], &in[576]));
                g2 neg_gamma_g2 =   g2::fromRawAffineBytesLE(std::span<const uint8_t, 192>(&in[576], &in[768]));
                g2 neg_delta_g2 =   g2::fromRawAffineBytesLE(std::span<const uint8_t, 192>(&in[768], &in[960]));
                std::vector<g1> ic;
                uint32_t n_ic = in[960] | in[961] << 8 | in[962] << 16 | in[963] << 24;
                ic.reserve(n_ic);
                for(uint32_t i = 0; i < n_ic; i++)
                {
                    ic.push_back(g1::fromRawAffineBytesLE(std::span<const uint8_t, 96>(&in[964 + i*96], &in[964 + (i+1)*96])));
                }
                return PreparedVerifyingKey(
                    alpha_g1_beta_g2,
                    neg_gamma_g2,
                    neg_delta_g2,
                    ic
                );
            }
        };

        bool verify_proof(
            const PreparedVerifyingKey& pvk,
            const Proof& proof,
            const std::vector<scalar>& public_inputs
        )
        {
            if(public_inputs.size() + 1 != pvk.ic.size())
            {
                return false;
            }

            g1 acc = pvk.ic[0];
            for(uint32_t i = 1; i < pvk.ic.size(); i++)
            {
                acc = acc.add(pvk.ic[i].mulScalar(public_inputs[i-1]));
            }

            std::vector<g1> g1_points; g1_points.reserve(3);
            std::vector<g2> g2_points; g2_points.reserve(3);
            g1_points.push_back(proof.a);   g2_points.push_back(proof.b);
            g1_points.push_back(acc);       g2_points.push_back(pvk.neg_gamma_g2);
            g1_points.push_back(proof.c);   g2_points.push_back(pvk.neg_delta_g2);
            return pvk.alpha_g1_beta_g2.equal(pairing::calculate(g1_points, g2_points));
        };
    } // namespace groth16
} // namespace bls12_381