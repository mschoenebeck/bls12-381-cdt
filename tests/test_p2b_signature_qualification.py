#!/usr/bin/env python3
"""P2B MOCK HOST-FLOW test: production XMD and Basic G2 signature paths.

Requires a C++20 compiler and OpenSSL development headers/library for a native
SHA-256 oracle. Host curve and pairing operations are deterministic MOCKS;
these tests do NOT establish BLS mathematical correctness or CDT/WASM safety.

Run: python3 tests/test_p2b_signature_qualification.py
"""
from __future__ import annotations
import hashlib
import os
import re
from pathlib import Path
import shutil
import subprocess
import tempfile

HEADER = Path(__file__).resolve().parents[1] / "bls12-381-cdt.hpp"
DST = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_"


def extract(src: str, signature: str) -> str:
    i = src.find(signature)
    if i < 0 or src.find(signature, i + 1) != -1:
        raise AssertionError("missing or ambiguous production signature: " + signature)
    start = src.find("{", i)
    if start < 0:
        raise AssertionError("no opening brace: " + signature)
    level = 0
    for j in range(start, len(src)):
        if src[j] == "{":
            level += 1
        elif src[j] == "}":
            level -= 1
            if level == 0:
                return src[i:j + 1]
    raise AssertionError("unbalanced braces: " + signature)


def xmd_reference(message: bytes, dst: bytes, length: int) -> bytes:
    """Independent Python RFC 9380 expand_message_xmd SHA-256 construction."""
    if not 0 <= len(dst) <= 255 or not 0 <= length <= 8160:
        raise ValueError("invalid input")
    if length == 0:
        return b""
    ell = (length + 31) // 32
    dst_prime = dst + bytes([len(dst)])
    b0 = hashlib.sha256(b"\0" * 64 + message + length.to_bytes(2, "big") + b"\0" + dst_prime).digest()
    b1 = hashlib.sha256(b0 + b"\1" + dst_prime).digest()
    blocks = [b1]
    for i in range(2, ell + 1):
        blocks.append(hashlib.sha256(bytes(x ^ y for x, y in zip(b0, blocks[-1])) + bytes([i]) + dst_prime).digest())
    return b"".join(blocks)[:length]


CPP = r'''
#include <algorithm>
#include <array>
#include <cassert>
#ifdef NDEBUG
#error "P2B requires active assertions"
#endif
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <limits>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>
#include <openssl/sha.h>
using std::size_t;
namespace eosio {
using bls_fp=std::array<uint8_t,48>;
using bls_fp2=std::array<bls_fp,2>;
using bls_s=std::array<uint8_t,64>;
using bls_scalar=std::array<uint8_t,32>;
using bls_g1=std::array<uint8_t,96>;
using bls_g2=std::array<uint8_t,192>;
using bls_gt=std::array<uint8_t,576>;
enum class fault {none, fp, map, map_second, add, identity, weighted_sum, weighted_identity, pairing, mismatch};
fault mode=fault::none;
int fp_calls=0,map_calls=0,add_calls=0,weighted_calls=0,pairing_calls=0;
std::array<bls_s,4> wide_inputs{};
std::array<bls_fp,4> reduced_outputs{};
std::array<bls_g2,2> mapped_outputs{};
bls_g2 latest_hash{};
std::array<bls_g2,2> expected_hashes{};
bls_g1 expected_pk1{},expected_pk2{},expected_negative_base{};
bls_g2 expected_signature{};
void reset(){mode=fault::none;fp_calls=map_calls=add_calls=weighted_calls=pairing_calls=0;}
void check(bool ok,const char* reason){if(!ok)throw std::runtime_error(reason);}
int32_t bls_fp_mod(const bls_s& in,bls_fp& out){
    if(fp_calls<4)wide_inputs[fp_calls]=in;
    ++fp_calls; if(mode==fault::fp)return 71;
    out.fill(0);out[0]=in[0];out[1]=in[63];reduced_outputs[(fp_calls-1)%4]=out;return 0;
}
int32_t bls_g2_map(const bls_fp2& x,bls_g2& out){
    ++map_calls;if(mode==fault::map||(mode==fault::map_second&&map_calls%2==0))return 72;
    const int map_index=(map_calls-1)%2;
    assert(x[0]==reduced_outputs[map_index*2]);
    assert(x[1]==reduced_outputs[map_index*2+1]);
    out.fill(0);out[0]=static_cast<uint8_t>(x[0][0]^x[1][0]);out[191]=0x5a;
    mapped_outputs[map_index]=out;
    return 0;
}
int32_t bls_g2_add(const bls_g2& a,const bls_g2& b,bls_g2& out){
    ++add_calls;if(mode==fault::add)return 73;
    assert(a==mapped_outputs[0] && b==mapped_outputs[1]);
    out.fill(0);
    if(mode!=fault::identity){out[0]=static_cast<uint8_t>(a[0]^b[0]^0x01);out[191]=0x5b;}
    latest_hash=out;
    return 0;
}
int32_t bls_g1_weighted_sum(const bls_g1* points,const bls_scalar* scalars,uint32_t n,bls_g1& out){
    ++weighted_calls;if(mode==fault::weighted_sum)return 74;
    assert(n>0);
    out.fill(0);for(uint32_t i=0;i<n;i++){
        assert(scalars[i][0]==1);
        for(size_t j=1;j<scalars[i].size();j++)assert(scalars[i][j]==0);
        out[0]=static_cast<uint8_t>(out[0]+points[i][0]);
    }
    if(mode==fault::weighted_identity)out.fill(0);
    return 0;
}
int32_t bls_pairing(const bls_g1* a,const bls_g2* b,uint32_t n,bls_gt& out){
    ++pairing_calls;if(mode==fault::pairing)return 75;
    // Full-buffer comparisons are deliberately independent of the production
    // hash_to_g2() input selection and its most recent output.
    assert(n==2 || n==3);
    assert(a[0]==expected_negative_base);
    assert(b[0]==expected_signature);
    assert(a[1]==expected_pk1);
    assert(b[1]==expected_hashes[0]);
    if(n==3){assert(a[2]==expected_pk2);assert(b[2]==expected_hashes[1]);}
    out.fill(0);out[0]=(mode==fault::mismatch)?2:1;return 0;
}
}
namespace bls12_381_cdt_detail {
std::array<uint8_t,32> sha256Digest(const std::vector<uint8_t>& bytes){
 std::array<uint8_t,32> out{};
 SHA256(bytes.data(),bytes.size(),out.data());return out;
}
}
namespace bls12_381 {
namespace ciphersuites {inline constexpr std::string_view basic_signature_g2 =
 "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";}
enum class signature_suite:uint8_t{basic};
__DST_METHOD__
enum class bls_errc:uint8_t{none,empty_input,invalid_length,length_mismatch,count_overflow,malformed_g1,malformed_g2,identity_point,wrong_subgroup,duplicate_message,host_operation_failed,unsupported_environment};
struct bls_error {bls_errc code=bls_errc::none;int32_t host_status=0;};
enum class signature_verdict:uint8_t{invalid,valid};
__RESULT_CLASS__;
namespace host_detail {__VALID_COUNT__}
__LONG_SCALAR__
struct scalar {eosio::bls_scalar raw{};scalar(uint64_t a,uint64_t,uint64_t,uint64_t){for(int i=0;i<8;i++)raw[i]=static_cast<uint8_t>(a>>(i*8));}const uint8_t* data()const{return raw.data();}};
struct g1 {eosio::bls_g1 raw{};const uint8_t* data()const{return raw.data();}
bool isIdentity()const{return std::all_of(raw.begin(),raw.end(),[](uint8_t x){return x==0;});}
operator eosio::bls_g1&(){return raw;}operator const eosio::bls_g1&()const{return raw;}static const g1 BASE_NEG;};
inline const g1 g1::BASE_NEG=[](){g1 p;p.raw[0]=0x91;return p;}();
struct g2 {eosio::bls_g2 raw{};uint8_t* data(){return raw.data();}const uint8_t* data()const{return raw.data();}bool isIdentity()const{return std::all_of(raw.begin(),raw.end(),[](uint8_t x){return x==0;});}
operator eosio::bls_g2&(){return raw;}operator const eosio::bls_g2&()const{return raw;}};
struct fp12 {eosio::bls_gt raw{};operator eosio::bls_gt&(){return raw;}
static fp12 one(){fp12 p;p.raw[0]=1;return p;}bool equal(const fp12& other)const{return raw==other.raw;}};
class validated_g1_affine_le {
 g1 p_;
 public: explicit validated_g1_affine_le(g1 p):p_(p){}
 const g1& point()const{return p_;}
 static validated_g1_affine_le from_trusted_point(const g1& p){return validated_g1_affine_le(p);}
};
class validated_g2_affine_le {
 g2 p_;
 public: explicit validated_g2_affine_le(g2 p):p_(p){}
 const g2& point()const{return p_;}
 static validated_g2_affine_le from_trusted_point(const g2& p){return validated_g2_affine_le(p);}
};
using binary_message_view=std::span<const uint8_t>;
__XMD__
__HASH_GENERIC__
__HASH_SUITE__
__AGG_KEYS__
__VERIFY__
__EQUAL_MSG__
__AGG_VERIFY__
}
using namespace bls12_381;
std::vector<uint8_t> decode(const std::string& h){
 assert(h.size()%2==0);std::vector<uint8_t> v;v.reserve(h.size()/2);
 for(size_t i=0;i<h.size();i+=2)v.push_back(static_cast<uint8_t>(std::stoul(h.substr(i,2),nullptr,16)));
 return v;
}
void printhex(const uint8_t* p,size_t n){const char* chars="0123456789abcdef";for(size_t i=0;i<n;i++){
 std::putchar(chars[p[i]>>4]);std::putchar(chars[p[i]&15]);}std::putchar('\n');}
int main(int argc,char** argv){
 assert(argc>=2);
 const std::string command=argv[1];
 if(command=="xmd"){
  assert(argc==6);const int n=std::stoi(argv[2]);auto msg=decode(argv[3]);auto dst=decode(argv[4]);
  const int invalid=std::stoi(argv[5]);std::vector<uint8_t> out(static_cast<size_t>(std::max(n,0)));
  try{xmd_sh256(out.data(),n,msg.data(),static_cast<int>(msg.size()),dst.data(),static_cast<int>(dst.size()));
   assert(!invalid);printhex(out.data(),out.size());}catch(const std::runtime_error&){assert(invalid);std::puts("invalid");}
 }else if(command=="hash"){
  assert(argc==4);auto msg=decode(argv[2]);auto dst=decode(argv[3]);eosio::reset();
  auto p=hash_to_g2(std::span<const uint8_t>(msg),std::string_view(reinterpret_cast<const char*>(dst.data()),dst.size()));
  assert(p.has_value());assert(eosio::fp_calls==4&&eosio::map_calls==2&&eosio::add_calls==1);
  for(const auto& s:eosio::wide_inputs)printhex(s.data(),s.size());
  printhex(p.value().point().data(),192);
 }else if(command=="flow"){
  assert(argc==4);
  const auto ah=decode(argv[2]),bh=decode(argv[3]);
  assert(ah.size()==192&&bh.size()==192);
  std::copy(ah.begin(),ah.end(),eosio::expected_hashes[0].begin());
  std::copy(bh.begin(),bh.end(),eosio::expected_hashes[1].begin());
  eosio::expected_negative_base.fill(0);eosio::expected_negative_base[0]=0x91;
  eosio::expected_pk1.fill(0);eosio::expected_pk1[0]=0x21;
  eosio::expected_pk2.fill(0);eosio::expected_pk2[0]=0x22;
  eosio::expected_signature.fill(0);eosio::expected_signature[0]=0x31;eosio::expected_signature[191]=0x5b;
  eosio::reset();g1 p1; p1.raw[0]=0x21;g1 p2;p2.raw[0]=0x22;
  g2 sig;sig.raw[0]=0x31;sig.raw[191]=0x5b;
  auto pk1=validated_g1_affine_le::from_trusted_point(p1);
  auto pk2=validated_g1_affine_le::from_trusted_point(p2);
  auto sg=validated_g2_affine_le::from_trusted_point(sig);
  std::vector<uint8_t> a{'a'},b{'b'};
  const auto valid=verify_basic_g2_signature(pk1,a,sg);
  assert(valid&&valid.value()==signature_verdict::valid&&eosio::pairing_calls==1);
  eosio::mode=eosio::fault::mismatch;
  const auto invalid_sig=verify_basic_g2_signature(pk1,a,sg);
  assert(invalid_sig&&invalid_sig.value()==signature_verdict::invalid);
  eosio::mode=eosio::fault::pairing;
  const auto bad=verify_basic_g2_signature(pk1,a,sg);
  assert(!bad&&bad.error().code==bls_errc::host_operation_failed&&bad.error().host_status==75);
  eosio::mode=eosio::fault::fp;
  const auto reduced=verify_basic_g2_signature(pk1,a,sg);
  assert(!reduced&&reduced.error().code==bls_errc::host_operation_failed&&reduced.error().host_status==71);
  eosio::mode=eosio::fault::none;
  std::array<validated_g1_affine_le,2> keys{pk1,pk2};
  const auto combined=aggregate_public_keys(keys);
  assert(combined&&combined.value().point().data()[0]==0x43);
  std::span<const validated_g1_affine_le> empty{};
  const auto none=aggregate_public_keys(empty);assert(!none&&none.error().code==bls_errc::empty_input);
  eosio::mode=eosio::fault::weighted_sum;
  const auto weighted=aggregate_public_keys(keys);
  assert(!weighted&&weighted.error().code==bls_errc::host_operation_failed&&weighted.error().host_status==74);
  eosio::mode=eosio::fault::weighted_identity;
  const auto zero_key=aggregate_public_keys(keys);
  assert(!zero_key&&zero_key.error().code==bls_errc::identity_point);
  eosio::mode=eosio::fault::none;
  std::array<binary_message_view,2> msgs{a,b};
  eosio::reset();
  const auto aggregate=aggregate_verify_basic(keys,msgs,sg);
  assert(aggregate&&aggregate.value()==signature_verdict::valid);
  eosio::mode=eosio::fault::mismatch;
  const auto ag_invalid=aggregate_verify_basic(keys,msgs,sg);
  assert(ag_invalid&&ag_invalid.value()==signature_verdict::invalid);
  eosio::mode=eosio::fault::none;
  std::array<binary_message_view,2> duplicate{a,a};
  const int before=eosio::pairing_calls;
  const auto repeated=aggregate_verify_basic(keys,duplicate,sg);
  assert(!repeated&&repeated.error().code==bls_errc::duplicate_message&&eosio::pairing_calls==before);
  const auto mismatch=aggregate_verify_basic(keys,std::span<const binary_message_view>(msgs.data(),1),sg);
  assert(!mismatch&&mismatch.error().code==bls_errc::length_mismatch);
  const auto no_keys=aggregate_verify_basic(empty,std::span<const binary_message_view>{},sg);
  assert(!no_keys&&no_keys.error().code==bls_errc::empty_input);
  eosio::reset();eosio::mode=eosio::fault::pairing;
  const auto ag_fail=aggregate_verify_basic(keys,msgs,sg);
  assert(!ag_fail&&ag_fail.error().host_status==75);
  eosio::reset();eosio::mode=eosio::fault::map;
  const auto map_fail=hash_to_g2(a,signature_suite::basic);
  assert(!map_fail&&map_fail.error().host_status==72);
  eosio::reset();eosio::mode=eosio::fault::map_second;
  const auto second_map_fail=hash_to_g2(a,signature_suite::basic);
  assert(!second_map_fail&&second_map_fail.error().host_status==72);
  eosio::reset();eosio::mode=eosio::fault::add;
  const auto add_fail=hash_to_g2(a,signature_suite::basic);
  assert(!add_fail&&add_fail.error().host_status==73);
  eosio::reset();eosio::mode=eosio::fault::identity;
  const auto identity_fail=hash_to_g2(a,signature_suite::basic);
  assert(!identity_fail&&identity_fail.error().code==bls_errc::identity_point);
  eosio::mode=eosio::fault::none;
  const auto invalid_dst=hash_to_g2(a,std::string(256,'x'));
  assert(!invalid_dst&&invalid_dst.error().code==bls_errc::invalid_length);
  std::puts("PASS P2B MOCK ONLY: complete signature/key/hash pairing buffers and error paths");
 }else return 2;
 return 0;
}
'''


def generated_source(header: str) -> str:
    if DST.decode() not in header:
        raise AssertionError("Basic ciphersuite DST changed")
    parts = {
        "DST_METHOD": "inline constexpr std::string_view ciphersuite_dst(const signature_suite)",
        "RESULT_CLASS": "template<class T>\n    class result",
        "VALID_COUNT": "inline bool valid_count_for_host(",
        "LONG_SCALAR": "inline std::array<uint64_t, 8> longScalarFromBytesBE(",
        "XMD": "inline void xmd_sh256(",
        "HASH_GENERIC": "inline result<validated_g2_affine_le> hash_to_g2(\n        const std::span<const uint8_t> message,\n        const std::string_view dst",
        "HASH_SUITE": "inline result<validated_g2_affine_le> hash_to_g2(\n        const std::span<const uint8_t> message,\n        const signature_suite suite",
        "AGG_KEYS": "inline result<validated_g1_affine_le> aggregate_public_keys(",
        "VERIFY": "inline result<signature_verdict> verify_basic_g2_signature(",
        "EQUAL_MSG": "inline bool equal_binary_messages(",
        "AGG_VERIFY": "inline result<signature_verdict> aggregate_verify_basic(",
    }
    source = CPP
    for key, signature in parts.items():
        source = source.replace("__" + key + "__", extract(header, signature))
    if "__HASH_" in source or "__RESULT_" in source:
        raise AssertionError("unfilled placeholders")
    return source


def run_case(exe: Path, *args: str) -> list[str]:
    process = subprocess.run([str(exe), *args], text=True, capture_output=True)
    if process.returncode:
        raise AssertionError(f"failed args={args!r} code={process.returncode} stderr={process.stderr[:1500]}")
    return process.stdout.splitlines()


def mock_hash_reference(msg: bytes, dst: bytes) -> bytes:
    """Independent Python oracle for the deterministic mock host mapping only.

    This is emphatically NOT the actual BLS12-381 hash-to-G2 output.
    """
    expanded = xmd_reference(msg, dst, 256)
    # Mock field reduction takes the least byte of the reversed 64-byte chunk;
    # each map XORs its two field elements; the mock G2 add XORs both maps.
    first = 1
    for i in range(4):
        first ^= expanded[i * 64 + 63]
    return bytes([first]) + bytes(190) + bytes([0x5B])


def exercise(exe: Path) -> None:
    cases = [
        (b"", DST, 0), (b"", DST, 32), (b"abc", DST, 64),
        (b"hello world", b"demo-DST", 128), (b"\0\xff\x01", b"", 255),
        (b"z" * 241, b"d" * 255, 256), (b"long message" * 80, DST, 512),
    ]
    for msg, dst, size in cases:
        actual = run_case(exe, "xmd", str(size), msg.hex(), dst.hex(), "0")
        expected = xmd_reference(msg, dst, size).hex()
        assert actual == [expected], (msg[:12], size, actual[:1], expected[:32])
    assert run_case(exe, "xmd", "8161", "00", DST.hex(), "1") == ["invalid"]
    assert run_case(exe, "xmd", "32", "00", (b"x" * 256).hex(), "1") == ["invalid"]
    for msg,dst in [(b"", DST),(b"abc", DST),(b"hello", b"custom-dst")]:
        actual = run_case(exe, "hash", msg.hex(), dst.hex())
        assert len(actual) == 5
        expanded = xmd_reference(msg,dst,256)
        expected_wide = [expanded[i:i+64][::-1].hex() for i in range(0,256,64)]
        assert actual[:4] == expected_wide, (actual[:4], expected_wide)
        assert len(actual[4]) == 384 and actual[4][-2:] == "5b"
    a_expected = mock_hash_reference(b"a", DST).hex()
    b_expected = mock_hash_reference(b"b", DST).hex()
    assert a_expected != b_expected, "test fixtures must distinguish hash outputs"
    assert run_case(exe, "flow", a_expected, b_expected) == [
        "PASS P2B MOCK ONLY: complete signature/key/hash pairing buffers and error paths"
    ]


def check_wrong_index_mutations(compiler: str, source: str, exe_dir: Path) -> None:
    """Actual source-level aggregate index mistakes must compile and fail at runtime."""
    cases = (
        ("message", r"hash_to_g2\(messages\[i\],\s*signature_suite::basic\)",
         "messages[i]", "messages[0]", "expected_hashes[1]"),
        ("public_key", r"grouped_public_keys\[i\]\.point\(\)",
         "grouped_public_keys[i]", "grouped_public_keys[0]", "expected_pk2"),
    )
    args = [mock_hash_reference(message, DST).hex() for message in (b"a", b"b")]
    for name, pattern, original, replacement, expected_error in cases:
        matches = list(re.finditer(pattern, source))
        assert len(matches) == 1, f"expected one aggregate {name} indexed call"
        at = matches[0]
        mutant = source[:at.start()] + at.group().replace(original, replacement) + source[at.end():]
        cpp = exe_dir / ("wrong_" + name + "_index.cpp")
        exe = exe_dir / ("wrong_" + name + "_index")
        cpp.write_text(mutant, encoding="utf-8")
        subprocess.run([compiler, "-std=c++20", "-O1", "-Wall", "-Wextra", "-Werror",
                        str(cpp), "-lcrypto", "-o", str(exe)], check=True)
        proc = subprocess.run([str(exe), "flow", *args], capture_output=True, text=True)
        if proc.returncode == 0:
            raise AssertionError(f"MUTATION SURVIVED: aggregate reused {name}[0]")
        if expected_error not in proc.stderr:
            raise AssertionError(f"mutation failed for an unrelated reason: {proc.stderr[-900:]}")


def main() -> None:
    header=HEADER.read_text(encoding="utf-8")
    source=generated_source(header)
    compilers=[os.environ["CXX"]] if os.getenv("CXX") else [c for c in ("g++","clang++") if shutil.which(c)]
    if not compilers:
        raise SystemExit("C++20 compiler required")
    for compiler in compilers:
        with tempfile.TemporaryDirectory(prefix="bls-p2b-") as d:
            cpp=Path(d)/"test.cpp"
            exe=Path(d)/"test"
            cpp.write_text(source,encoding="utf-8")
            subprocess.run([compiler,"-std=c++20","-O1","-Wall","-Wextra","-Werror",str(cpp),"-lcrypto","-o",str(exe)],check=True)
            exercise(exe)
            check_wrong_index_mutations(compiler, source, Path(d))
            print("PASS P2B MOCK/XMD:", compiler,
                  "independent SHA256/XMD oracle and complete pairing argument binding")
    print("NOT QUALIFIED: mock pairing cannot prove BLS; run test_p2b_real_vectors.py"
          " against a real BLS backend and production CDT/WASM contract.")


if __name__=="__main__":
    main()
