#!/usr/bin/env python3
"""P2-A host-boundary qualification for *actual extracted production method bodies*.

Tests direct-output BLS ABI, error propagation, early rejection and bound checking
without Antelope CDT. Compiles original P0 methods and P1 validated-G1/G2 methods
using deterministic mock native intrinsics. This is NOT cryptographic or WASM testing.

Usage from the bls12-381-cdt repository:
  python3 tests/test_p2_lean_host_boundary.py
  CXX=clang++ python3 tests/test_p2_lean_host_boundary.py
"""
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

HEADER = Path(__file__).resolve().parents[1] / "bls12-381-cdt.hpp"


def extract(header, signature):
    start = header.find(signature)
    if start < 0 or header.find(signature, start + 1) >= 0:
        raise AssertionError("missing or ambiguous production method: " + signature)
    pos = header.find("{", start)
    depth = 0
    for i in range(pos, len(header)):
        if header[i] == "{":
            depth += 1
        elif header[i] == "}":
            depth -= 1
            if depth == 0:
                return header[start : i + 1]
    raise AssertionError("unclosed production method: " + signature)


def p1_source_checks(header):
    # Architectural invariant only; runtime behavior is tested from extracted bodies.
    # Do not freeze incidental method wording, line counts or documentation text.
    assert "inline result<eosio::bls_" not in header, "large host-result wrappers reintroduced"
    assert "host_failure(const int32_t status)" not in header, "dead host-failure wrapper reintroduced"
    assert not re.search(r"host_detail::(?!valid_count_for_host)[a-z_]+\(", header), (
        "large host-result call path reintroduced"
    )


COMMON = r'''
#include <array>
#include <cassert>
#include <cstdint>
#include <cstddef>
#include <cstdio>
#include <cstring>
#include <limits>
#include <optional>
#include <span>
#include <stdexcept>
#include <vector>
using std::size_t;
namespace eosio {
using bls_fp = std::array<uint8_t,48>;
using bls_fp2 = std::array<bls_fp,2>;
using bls_g1 = std::array<uint8_t,96>;
using bls_g2 = std::array<uint8_t,192>;
using bls_gt = std::array<uint8_t,576>;
using bls_scalar = std::array<uint8_t,32>;
using bls_s = std::array<uint8_t,64>;
int32_t next_status = 0;
int calls = 0;
uint32_t last_count = 0;
void check(bool cond, const char* msg) {if(!cond)throw std::runtime_error(msg);}
template<class T>int32_t outcall(T& out){++calls;out.fill(0);out[0]=0x6a;return next_status;}
int32_t bls_fp_mod(const bls_s&,bls_fp& out){return outcall(out);}
int32_t bls_g1_add(const bls_g1&,const bls_g1&,bls_g1& out){return outcall(out);}
int32_t bls_g2_add(const bls_g2&,const bls_g2&,bls_g2& out){return outcall(out);}
int32_t bls_g1_weighted_sum(const bls_g1*,const bls_scalar*,uint32_t n,bls_g1& out){last_count=n;return outcall(out);}
int32_t bls_g2_weighted_sum(const bls_g2*,const bls_scalar*,uint32_t n,bls_g2& out){last_count=n;return outcall(out);}
int32_t bls_pairing(const bls_g1*,const bls_g2*,uint32_t n,bls_gt& out){last_count=n;return outcall(out);}
int32_t bls_g1_map(const bls_fp&,bls_g1& out){return outcall(out);}
int32_t bls_g2_map(const bls_fp2&,bls_g2& out){return outcall(out);}
}
namespace host_detail {
__VALID_COUNT_HELPER__
}
struct scalar {eosio::bls_scalar val{};const uint8_t* data()const{return val.data();}};
struct fp {eosio::bls_fp value{};operator eosio::bls_fp&(){return value;}operator const eosio::bls_fp&()const{return value;}
__FP__
};
struct fp2{eosio::bls_fp2 value{};operator const eosio::bls_fp2&()const{return value;}};
struct g1{eosio::bls_g1 value{};const uint8_t* data()const{return value.data();}
operator eosio::bls_g1&(){return value;}operator const eosio::bls_g1&()const{return value;}
__G1__
};
struct g2{eosio::bls_g2 value{};const uint8_t* data()const{return value.data();}
operator eosio::bls_g2&(){return value;}operator const eosio::bls_g2&()const{return value;}
__G2__
};
struct fp12{eosio::bls_gt value{};operator eosio::bls_gt&(){return value;}};
namespace pairing{__PAIR__}
int main(){
 scalar s;scalar scalars[2]{};fp base;fp2 base2;g1 g1s[2]{};g2 g2s[2]{};
 const size_t max_uint32 = std::numeric_limits<uint32_t>::max();
 for(size_t element : {sizeof(eosio::bls_scalar), sizeof(eosio::bls_g1), sizeof(eosio::bls_g2)}) {
  const size_t maximum = max_uint32 / element;
  assert(!host_detail::valid_count_for_host(0, element));
  assert(host_detail::valid_count_for_host(1, element));
  assert(host_detail::valid_count_for_host(maximum, element));
  assert(!host_detail::valid_count_for_host(maximum + 1, element));
  assert(!host_detail::valid_count_for_host(max_uint32 + size_t{1}, element));
 }
 auto pass=[](auto f){eosio::next_status=0;int before=eosio::calls;auto r=f();assert(eosio::calls==before+1);assert(r.value[0]==0x6a);};
 auto fail=[](auto f){eosio::next_status=53;int before=eosio::calls;bool rejected=false;try{(void)f();}catch(const std::runtime_error&){rejected=true;}assert(rejected && eosio::calls==before+1);};
 auto invalid=[](auto f){eosio::next_status=0;int before=eosio::calls;bool rejected=false;try{(void)f();}catch(const std::runtime_error&){rejected=true;}assert(rejected && eosio::calls==before);};
 std::array<uint64_t,8> wide{};
 pass([&]{return fp::modPrime(wide);});fail([&]{return fp::modPrime(wide);});
 pass([&]{return g1s[0].add(g1s[1]);});fail([&]{return g1s[0].add(g1s[1]);});
 pass([&]{return g1s[0].mulScalar(s);});fail([&]{return g1s[0].mulScalar(s);});
 pass([&]{return g1::multiExp(g1s,scalars,2);});assert(eosio::last_count==2);
 fail([&]{return g1::multiExp(g1s,scalars,1);});invalid([&]{return g1::multiExp(g1s,scalars,0);});
 invalid([&]{return g1::multiExp(g1s,scalars, static_cast<uint32_t>(max_uint32 / sizeof(eosio::bls_g1) + 1));});
 pass([&]{return g1::mapToCurve(base);});fail([&]{return g1::mapToCurve(base);});
 pass([&]{return g2s[0].add(g2s[1]);});fail([&]{return g2s[0].add(g2s[1]);});
 pass([&]{return g2s[0].mulScalar(s);});fail([&]{return g2s[0].mulScalar(s);});
 pass([&]{return g2::multiExp(g2s,scalars,2);});assert(eosio::last_count==2);
 fail([&]{return g2::multiExp(g2s,scalars,1);});invalid([&]{return g2::multiExp(g2s,scalars,0);});
 invalid([&]{return g2::multiExp(g2s,scalars, static_cast<uint32_t>(max_uint32 / sizeof(eosio::bls_g2) + 1));});
 pass([&]{return g2::mapToCurve(base2);});fail([&]{return g2::mapToCurve(base2);});
 pass([&]{return pairing::calculate(g1s,g2s,2);});assert(eosio::last_count==2);
 fail([&]{return pairing::calculate(g1s,g2s,1);});invalid([&]{return pairing::calculate(g1s,g2s,0);});
 invalid([&]{return pairing::calculate(g1s,g2s, static_cast<uint32_t>(max_uint32 / sizeof(eosio::bls_g2) + 1));});
 std::puts("PASS P2-A: ten extracted production methods, direct output, failure propagation, zero and oversized counts");
}
'''


def p0_harness(header):
    types = {
        "FP": ["static fp modPrime("],
        "G1": ["g1 add(", "g1 mulScalar(", "static g1 multiExp(", "static g1 mapToCurve("],
        "G2": ["g2 add(", "g2 mulScalar(", "static g2 multiExp(", "static g2 mapToCurve("],
        "PAIR": ["inline fp12 calculate("],
    }
    source = COMMON
    for key, sigs in types.items():
        parts = "\n".join(extract(header, sig) for sig in sigs)
        source = source.replace("__" + key + "__", parts)
    return source.replace(
        "__VALID_COUNT_HELPER__", extract(header, "inline bool valid_count_for_host(")
    )


def build_run(source, compiler, label):
    with tempfile.TemporaryDirectory(prefix="bls-p2-" + label + "-") as directory:
        cpp = Path(directory) / "oracle.cpp"
        binary = Path(directory) / "oracle"
        cpp.write_text(source)
        subprocess.run([compiler, "-std=c++20", "-O1", "-Wall", "-Wextra", "-Werror", str(cpp), "-o", str(binary)], check=True)
        subprocess.run([str(binary)], check=True)


VALIDATED_COMMON = r'''
#include <array>
#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <optional>
#include <utility>
namespace eosio {
using bls_g1 = std::array<uint8_t,96>;
using bls_g2 = std::array<uint8_t,192>;
using bls_scalar = std::array<uint8_t,32>;
enum class fault {none, canonical_error, canonical_identity, subgroup_error, wrong_subgroup};
fault mode = fault::none;
int calls = 0;
int32_t bls_g1_add(const bls_g1&, const bls_g1&,bls_g1& out){
 ++calls; if(mode==fault::canonical_error)return 51;
 out.fill(0); if(mode!=fault::canonical_identity){out[0]=0xc1;out[95]=0x5a;}return 0;
}
int32_t bls_g2_add(const bls_g2&, const bls_g2&,bls_g2& out){
 ++calls; if(mode==fault::canonical_error)return 52;
 out.fill(0); if(mode!=fault::canonical_identity){out[0]=0xc2;out[191]=0x5b;}return 0;
}
int32_t bls_g1_weighted_sum(const bls_g1* points, const bls_scalar*, uint32_t n,bls_g1& out){
 ++calls; assert(n==1);
 assert(points != nullptr && (*points)[0]==0xc1 && (*points)[95]==0x5a);
 if(mode==fault::subgroup_error)return 61;
 out.fill(0); if(mode==fault::wrong_subgroup)out[0]=1;return 0;
}
int32_t bls_g2_weighted_sum(const bls_g2* points, const bls_scalar*, uint32_t n,bls_g2& out){
 ++calls; assert(n==1);
 assert(points != nullptr && (*points)[0]==0xc2 && (*points)[191]==0x5b);
 if(mode==fault::subgroup_error)return 62;
 out.fill(0); if(mode==fault::wrong_subgroup)out[0]=1;return 0;
}
}
enum class bls_errc : uint8_t {none, malformed_g1, malformed_g2, identity_point, host_operation_failed, wrong_subgroup};
struct bls_error {bls_errc code=bls_errc::none;int32_t host_status=0;};
template<typename T>class result {
 std::optional<T> val;bls_error err;
 public:
 static result success(T value){return result(std::move(value));}
 static result failure(bls_errc code,int32_t status=0){return result(bls_error{code,status});}
 bool has_value()const{return val.has_value();}
 const bls_error& error()const{return err;}
 private:
 explicit result(T value):val(std::move(value)){}
 explicit result(bls_error e):err(e){}
};
struct scalar {
 static const std::array<uint8_t,32> Q;
};
const std::array<uint8_t,32> scalar::Q = {1};
struct g1 {
 eosio::bls_g1 data_{};
 operator const eosio::bls_g1&()const{return data_;}
 operator eosio::bls_g1&(){return data_;}
 bool isIdentity()const{for(uint8_t x:data_)if(x)return false;return true;}
};
struct g2 {
 eosio::bls_g2 data_{};
 operator const eosio::bls_g2&()const{return data_;}
 operator eosio::bls_g2&(){return data_;}
 bool isIdentity()const{for(uint8_t x:data_)if(x)return false;return true;}
};
struct validated_g1_affine_le {
 g1 point_;
 explicit validated_g1_affine_le(const g1& p):point_(p){}
 __VAL_G1__
};
struct validated_g2_affine_le {
 g2 point_;
 explicit validated_g2_affine_le(const g2& p):point_(p){}
 __VAL_G2__
};
template <typename Input,typename F>
void test(F&& fun,bls_errc malformed,int32_t malformed_status,int32_t subgroup_status){
 Input point{};
 point.data_[0]=0x21; point.data_.back()=0x22;  // Deliberately distinct from canonicalized output.
 using eosio::fault;
 const fault modes[]={fault::none,fault::canonical_error,fault::canonical_identity,
                      fault::subgroup_error,fault::wrong_subgroup};
 for(fault f:modes){
  eosio::mode=f;eosio::calls=0;
  auto response=fun(point);
  if(f==fault::none){assert(response.has_value());assert(eosio::calls==2);continue;}
  assert(!response.has_value());
  if(f==fault::canonical_error){assert(eosio::calls==1);assert(response.error().code==malformed);
     assert(response.error().host_status==malformed_status);}
  else if(f==fault::canonical_identity){assert(eosio::calls==1);
     assert(response.error().code==bls_errc::identity_point);}
  else if(f==fault::subgroup_error){assert(eosio::calls==2);
     assert(response.error().code==bls_errc::host_operation_failed);
     assert(response.error().host_status==subgroup_status);}
  else {assert(eosio::calls==2);assert(response.error().code==bls_errc::wrong_subgroup);}
 }
}
int main(){
 test<g1>([](const g1& p){return validated_g1_affine_le::from_point(p);},bls_errc::malformed_g1,51,61);
 test<g2>([](const g2& p){return validated_g2_affine_le::from_point(p);},bls_errc::malformed_g2,52,62);
 std::puts("PASS P2-A: production P1 validated G1/G2 constructors, five fault modes each");
}
'''


def validated_harness(header):
    return (VALIDATED_COMMON
            .replace("__VAL_G1__", extract(header, "static result<validated_g1_affine_le> from_point(const g1& point)"))
            .replace("__VAL_G2__", extract(header, "static result<validated_g2_affine_le> from_point(const g2& point)")))


def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--header", type=Path, default=HEADER)
    parser.add_argument("--p0-only", action="store_true", help="Fixture mode: run extracted P0 methods only")
    args = parser.parse_args()
    header = args.header.read_text()
    if not args.p0_only:
        p1_source_checks(header)
        print("PASS P2-A: no large host-result wrappers remain")
    compilers = [os.environ["CXX"]] if os.environ.get("CXX") else [c for c in ("g++", "clang++") if shutil.which(c)]
    if not compilers:
        raise SystemExit("No native C++20 compiler found")
    for compiler in compilers:
        build_run(p0_harness(header), compiler, "p0")
        if not args.p0_only:
            build_run(validated_harness(header), compiler, "validated")
    print("NOTE: host mocks only; cryptographic vectors and actual Antelope CDT/WASM NOT RUN")


if __name__ == "__main__":
    main()
