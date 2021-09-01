#include <iostream>

#include <nil/crypto3/zk/snark/schemes/ppzksnark/r1cs_gg_ppzksnark.hpp>
#include <nil/crypto3/zk/snark/schemes/ppzksnark/r1cs_gg_ppzksnark/marshalling.hpp>


typedef algebra::curves::bls12<381> curve_type;
typedef curve_type::scalar_field_type field_type;
typedef field_type::value_type value_type;
typedef zk::snark::r1cs_gg_ppzksnark<curve_type> scheme_type;
typedef nil::marshalling::verifier_input_serializer_tvm<scheme_type> serializer_tvm;
typedef nil::marshalling::verifier_input_deserializer_tvm<scheme_type> deserializer_tvm;

constexpr const std::size_t modulus_bits = field_type::modulus_bits;
constexpr const std::size_t modulus_chunks = modulus_bits / 8 + (modulus_bits % 8 ? 1 : 0);

std::vector<bool> merge_vectors(const std::vector<bool> left_bv, const std::vector<bool> right_bv) {
    std::vector<bool> result;
    result.insert(result.end(), left_bv.begin(), left_bv.end());
    result.insert(result.end(), right_bv.begin(), right_bv.end());

    return result;
}

std::vector<bool> bitset_to_bitvector(const std::bitset<256> bs) {
  std::vector<bool> result(256);
  for (uint i = 0; i < 256; i++) {
    result[i] = bs[255 - i];
  }
  return result;
}

std::vector<bool> uint_to_bitvector(const uint number) {
  return bitset_to_bitvector(std::bitset<256>(number));
}


// Thanks @NoamDev for this two functions:
std::string field_element_to_hex(value_type element) {
    std::string hex;
    std::vector<std::uint8_t> byteblob(modulus_chunks);
    std::vector<std::uint8_t>::iterator write_iter = byteblob.begin();
    serializer_tvm::field_type_process<field_type>(element, write_iter);
    boost::algorithm::hex(byteblob.begin(), byteblob.end(), std::back_inserter(hex));
    return hex;
}

value_type hex_to_field_element(const std::string& hex) {
    std::vector<uint8_t> hash_bytes(modulus_chunks);
    boost::algorithm::unhex(hex.begin(), hex.end(), hash_bytes.begin());

    nil::marshalling::status_type status;
    value_type result =
        deserializer_tvm::field_type_process<field_type>(hash_bytes.begin(), hash_bytes.end(), status);

    return result;
}
