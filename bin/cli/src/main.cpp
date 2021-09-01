#include <boost/algorithm/hex.hpp>
#include <boost/filesystem.hpp>
#include <boost/program_options.hpp>

#include <nil/crypto3/algebra/curves/bls12.hpp>
#include <nil/crypto3/algebra/fields/bls12/base_field.hpp>
#include <nil/crypto3/algebra/fields/bls12/scalar_field.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/bls12.hpp>
#include <nil/crypto3/algebra/curves/params/multiexp/bls12.hpp>
#include <nil/crypto3/algebra/curves/params/wnaf/bls12.hpp>
#include <nil/crypto3/algebra/pairing/bls12.hpp>
#include <nil/crypto3/algebra/pairing/mnt4.hpp>
#include <nil/crypto3/algebra/pairing/mnt6.hpp>

#include <nil/crypto3/zk/components/blueprint.hpp>
#include <nil/crypto3/zk/components/blueprint_variable.hpp>
#include <nil/crypto3/zk/components/disjunction.hpp>

#include <nil/crypto3/zk/snark/schemes/ppzksnark/r1cs_gg_ppzksnark.hpp>
#include <nil/crypto3/zk/snark/schemes/ppzksnark/r1cs_gg_ppzksnark/marshalling.hpp>

#include <nil/crypto3/zk/snark/algorithms/generate.hpp>
#include <nil/crypto3/zk/snark/algorithms/verify.hpp>
#include <nil/crypto3/zk/snark/algorithms/prove.hpp>

#include <nil/marshalling/status_type.hpp>
#include <nil/crypto3/marshalling/types/zk/r1cs_gg_ppzksnark/primary_input.hpp>
#include <nil/crypto3/marshalling/types/zk/r1cs_gg_ppzksnark/proof.hpp>
#include <nil/crypto3/marshalling/types/zk/r1cs_gg_ppzksnark/verification_key.hpp>

#include "detail/multiscore_component.hpp"

using Endianness = nil::marshalling::option::big_endian;
using unit_type = unsigned char;

boost::filesystem::path PROVING_KEY_PATH = "p_key";
boost::filesystem::path VERIFICATION_KEY_PATH = "v_key";
boost::filesystem::path PROOF_PATH = "proof";
boost::filesystem::path INPUT_PATH = "pi";

std::vector<std::uint8_t> readfile(boost::filesystem::path path) {
    boost::filesystem::ifstream stream(path, std::ios::in | std::ios::binary);
    auto eos = std::istreambuf_iterator<char>();
    auto buffer = std::vector<uint8_t>(std::istreambuf_iterator<char>(stream), eos);
    return buffer;
}

bool trusted_setup() {
    std::cout << std::endl;
    std::cout << "Generating keys..." << std::endl;
    std::cout << std::endl;
    blueprint<field_type> bp;
    multiscore<field_type> multiscore(bp);
    multiscore.generate_r1cs_constraints();

    const r1cs_constraint_system<field_type> constraint_system = bp.get_constraint_system();

    scheme_type::keypair_type keypair = generate<scheme_type>(constraint_system);

    std::vector<std::uint8_t> proving_key_byteblob =
        nil::marshalling::verifier_input_serializer_tvm<scheme_type>::process(keypair.first);

    using verification_key_marshalling_type = nil::crypto3::marshalling::types::r1cs_gg_ppzksnark_verification_key<
        nil::marshalling::field_type<
            Endianness>,
        typename scheme_type::verification_key_type>;

    verification_key_marshalling_type filled_verification_key_val =
        nil::crypto3::marshalling::types::fill_r1cs_gg_ppzksnark_verification_key<
            typename scheme_type::verification_key_type,
            Endianness>(keypair.second);


    std::vector<unit_type> verification_key_byteblob;
    verification_key_byteblob.resize(filled_verification_key_val.length(), 0x00);
    auto verification_key_write_iter = verification_key_byteblob.begin();

    typename nil::marshalling::status_type status =
        filled_verification_key_val.write(verification_key_write_iter,
            verification_key_byteblob.size());

    boost::filesystem::ofstream pk_out(PROVING_KEY_PATH);
    for (const auto &v : proving_key_byteblob) {
        pk_out << v;
    }
    pk_out.close();
    std::cout << "Proving key is saved to " << PROVING_KEY_PATH << std::endl;

    boost::filesystem::ofstream vk_out(VERIFICATION_KEY_PATH );
    for (const auto &v : verification_key_byteblob) {
        vk_out << v;
    }
    vk_out.close();
    std::cout << "Verification key is saved to " << VERIFICATION_KEY_PATH << std::endl;

    return true;
}


bool proof_generation(uint pa_id, uint pa_income, uint fi_overdue_loans, uint fi_account_age, std::string pa_data_hash, std::string fi_data_hash) {
    std::cout << std::endl;
    std::cout << "Proving..." << std::endl;
    std::cout << std::endl;

    std::vector<std::uint8_t> proving_key_byteblob = readfile(PROVING_KEY_PATH);
    nil::marshalling::status_type provingProcessingStatus = nil::marshalling::status_type::success;
    typename scheme_type::proving_key_type proving_key = nil::marshalling::verifier_input_deserializer_tvm<scheme_type>::proving_key_process(
        proving_key_byteblob.cbegin(),
        proving_key_byteblob.cend(),
        provingProcessingStatus);

    std::vector<std::uint8_t> ver_key_byteblob = readfile(VERIFICATION_KEY_PATH);
    nil::marshalling::status_type verProcessingStatus = nil::marshalling::status_type::success;
    typename scheme_type::verification_key_type verification_key = nil::marshalling::verifier_input_deserializer_tvm<scheme_type>::verification_key_process(
        ver_key_byteblob.cbegin(),
        ver_key_byteblob.cend(),
        verProcessingStatus);

    blueprint<field_type> bp;
    multiscore<field_type> multiscore(bp);
    multiscore.generate_r1cs_constraints();
    multiscore.generate_r1cs_witness(pa_id, pa_income, fi_overdue_loans, fi_account_age, pa_data_hash, fi_data_hash);

    std::cout << "Blueprint is satisfied: " << bp.is_satisfied() << std::endl;
    if (!bp.is_satisfied()) {
        return false;
    }



    // Proof
    const scheme_type::proof_type proof = prove<scheme_type>(proving_key, bp.primary_input(), bp.auxiliary_input());



    // PROOF AND INPUT FILE EXPORT
    // (new marshalling)
    // ===============================================================================

    using proof_marshalling_type = nil::crypto3::marshalling::types::r1cs_gg_ppzksnark_proof<
        nil::marshalling::field_type<
            Endianness>,
        typename scheme_type::proof_type>;

    proof_marshalling_type filled_proof_val =
        nil::crypto3::marshalling::types::fill_r1cs_gg_ppzksnark_proof<
            typename scheme_type::proof_type,
            Endianness>(proof);

    using primary_input_marshalling_type = nil::crypto3::marshalling::types::r1cs_gg_ppzksnark_primary_input<
        nil::marshalling::field_type<
            Endianness>,
        typename scheme_type::primary_input_type>;

    primary_input_marshalling_type filled_primary_input_val =
        nil::crypto3::marshalling::types::fill_r1cs_gg_ppzksnark_primary_input<
            typename scheme_type::primary_input_type,
            Endianness>(bp.primary_input());

    /* std::cout << "Marshalling types filled." << std::endl; */

    std::vector<unit_type> proof_byteblob;
    proof_byteblob.resize(filled_proof_val.length(), 0x00);
    auto proof_write_iter = proof_byteblob.begin();

    typename nil::marshalling::status_type status;
    status = filled_proof_val.write(proof_write_iter,
            proof_byteblob.size());

    std::vector<unit_type> primary_input_byteblob;

    primary_input_byteblob.resize(filled_primary_input_val.length(), 0x00);
    auto primary_input_write_iter = primary_input_byteblob.begin();

    status = filled_primary_input_val.write(primary_input_write_iter,
            primary_input_byteblob.size());

    /* std::cout << "Byteblobs filled." << std::endl; */

    boost::filesystem::ofstream proof_out(PROOF_PATH);
    for (const auto &v : proof_byteblob) {
        proof_out << v;
    }
    proof_out.close();
    std::cout << "Proof is saved to " << PROOF_PATH << std::endl;

    boost::filesystem::ofstream primary_input_out(INPUT_PATH);
    for (const auto &v : primary_input_byteblob) {
        primary_input_out << v;
    }
    primary_input_out.close();
    std::cout << "Primary input is saved to " << INPUT_PATH << std::endl;



    // TEST VERIFICATION
    // ===============================================================================

    /* std::cout << std::endl; */
    /* std::cout << "Verification..." << std::endl; */
    /* using basic_proof_system = r1cs_gg_ppzksnark<curve_type>; */
    /* const bool verified = verify<basic_proof_system>(verification_key, bp.primary_input(), proof); */
    /* std::cout << "Proof is verified: " << verified << std::endl; */

    // ===============================================================================
    // ===============================================================================

    return true;
}


int main(int argc, char *argv[]) {
    uint pa_id, pa_income, fi_overdue_loans, fi_account_age;
    std::string pa_data_hash, fi_data_hash;

    boost::program_options::options_description options(
        "R1CS Generic Group PreProcessing Zero-Knowledge Succinct Non-interactive ARgument of Knowledge "
        "(https://eprint.iacr.org/2016/260.pdf) CLI Proof Generator");
    options.add_options()
    ("help", "Display help message")
    ("setup", "Trusted setup phase: key generation")
    ("proof", "Proof generation")
    ("id,a", boost::program_options::value<uint>(&pa_id)->default_value(123))
    ("income,b", boost::program_options::value<uint>(&pa_income)->default_value(100))
    ("overdue-loans,c", boost::program_options::value<uint>(&fi_overdue_loans)->default_value(0))
    ("account-age,d", boost::program_options::value<uint>(&fi_account_age)->default_value(0))
    ("pa-data-hash,e", boost::program_options::value<std::string>(&pa_data_hash)->default_value(""))
    ("fi-data-hash,f", boost::program_options::value<std::string>(&fi_data_hash)->default_value(""));

    boost::program_options::variables_map vm;
    boost::program_options::store(boost::program_options::command_line_parser(argc, argv).options(options).run(), vm);
    boost::program_options::notify(vm);

    if (vm.count("help") || argc < 2) {
        std::cout << options << std::endl;
        return 0;
    } else if (vm.count("setup")) {
        trusted_setup();
    } else if (vm.count("proof")) {
        proof_generation(pa_id, pa_income, fi_overdue_loans, fi_account_age, pa_data_hash, fi_data_hash);
    }
    return 0;
}
