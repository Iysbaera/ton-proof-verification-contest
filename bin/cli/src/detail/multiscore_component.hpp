#include <iostream>

#include <nil/crypto3/algebra/curves/bls12.hpp>
#include <nil/crypto3/algebra/fields/bls12/base_field.hpp>
#include <nil/crypto3/algebra/fields/bls12/scalar_field.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/bls12.hpp>
#include <nil/crypto3/algebra/curves/params/multiexp/bls12.hpp>
#include <nil/crypto3/algebra/curves/params/wnaf/bls12.hpp>

#include <nil/crypto3/zk/components/blueprint.hpp>
#include <nil/crypto3/zk/components/blueprint_variable.hpp>
#include <nil/crypto3/zk/components/comparison.hpp>
#include <nil/crypto3/zk/components/hashes/knapsack/knapsack_component.hpp>

#include <nil/crypto3/zk/snark/schemes/ppzksnark/r1cs_gg_ppzksnark.hpp>
#include <nil/crypto3/zk/snark/schemes/ppzksnark/r1cs_gg_ppzksnark/marshalling.hpp>


#include "../utils.hpp"
#include "knapsack_packing_component.hpp"

using namespace nil::crypto3;
using namespace nil::crypto3::zk;
using namespace nil::crypto3::zk::components;
using namespace nil::crypto3::algebra;
using namespace nil::crypto3::zk::snark;

typedef algebra::curves::bls12<381> curve_type;
typedef curve_type::scalar_field_type field_type;
typedef field_type::value_type value_type;



template<typename FieldT>
class multiscore : public component<FieldT> {

  public:
    blueprint_variable<FieldT> out;

    // Weights
    blueprint_variable<FieldT> score_base;
    blueprint_variable<FieldT> W_PA_income;
    blueprint_variable<FieldT> W_FI_overdue_loans;
    blueprint_variable<FieldT> W_FI_account_age;

    // Data from Public Agencies
    blueprint_variable<FieldT> PA_id;
    blueprint_variable<FieldT> PA_income;

    // Data from Financial Institutions
    blueprint_variable<FieldT> FI_overdue_loans;
    blueprint_variable<FieldT> FI_account_age;

    blueprint_variable<FieldT> score_min;
    blueprint_variable<FieldT> score_min_lt;
    blueprint_variable<FieldT> score_min_lte;

    blueprint_variable<FieldT> score;

    blueprint_variable<FieldT> PRIV_HASH_PA_data;
    blueprint_variable<FieldT> PUB_HASH_PA_data;

    blueprint_variable<FieldT> PRIV_HASH_FI_data;
    blueprint_variable<FieldT> PUB_HASH_FI_data;

    // Intermediate variables
    blueprint_variable<FieldT> interm1;
    blueprint_variable<FieldT> interm2;
    blueprint_variable<FieldT> interm3;

    blueprint_variable<FieldT> HASH_PA_validation_result;
    blueprint_variable<FieldT> HASH_FI_validation_result;

    std::shared_ptr<digest_variable<FieldT>> digest_PA_id;
    std::shared_ptr<digest_variable<FieldT>> digest_PA_income;

    std::shared_ptr<digest_variable<FieldT>> bits_FI_overdue_loans;
    std::shared_ptr<digest_variable<FieldT>> bits_FI_account_age;

    std::shared_ptr<comparison<FieldT>> score_min_comparator;

    std::shared_ptr<knapsack_field_packing_component<FieldT>> pa_data_knapsack;
    std::shared_ptr<knapsack_field_packing_component<FieldT>> fi_data_knapsack;

  multiscore(blueprint<FieldT> &bp): component<FieldT>(bp) {
    // Public inputs
    score_base.allocate(this->bp);
    score_min.allocate(this->bp);

    PUB_HASH_PA_data.allocate(this->bp);
    PUB_HASH_FI_data.allocate(this->bp);

    HASH_PA_validation_result.allocate(this->bp);
    HASH_FI_validation_result.allocate(this->bp);
    out.allocate(this->bp);

    // Weights
    W_PA_income.allocate(this->bp);
    W_FI_overdue_loans.allocate(this->bp);
    W_FI_account_age.allocate(this->bp);

    // Data from Public Agencies
    PA_id.allocate(this->bp);
    PA_income.allocate(this->bp);

    // Data from Financial Institutions
    FI_overdue_loans.allocate(this->bp);
    FI_account_age.allocate(this->bp);

    PRIV_HASH_PA_data.allocate(this->bp);
    PRIV_HASH_FI_data.allocate(this->bp);

    // Intermediate variables
    interm1.allocate(this->bp);
    interm2.allocate(this->bp);
    interm3.allocate(this->bp);

    score_min_lt.allocate(this->bp);
    score_min_lte.allocate(this->bp);

    score.allocate(this->bp);

    this->bp.set_input_sizes(7);
  }






  void generate_r1cs_constraints() {
    score_min_comparator.reset(new comparison<FieldT>(this->bp,
      50, // size
      score_min, // X
      score, // Y
      score_min_lt, // X > Y
      score_min_lte)); // X >= Y
    score_min_comparator.get()->generate_r1cs_constraints();

    // Ensure score validity
    this->bp.add_r1cs_constraint(r1cs_constraint<FieldT>(FI_account_age, W_FI_account_age, interm1));
    this->bp.add_r1cs_constraint(r1cs_constraint<FieldT>(FI_overdue_loans, FI_overdue_loans, interm2));
    this->bp.add_r1cs_constraint(r1cs_constraint<FieldT>(interm2, W_FI_overdue_loans, interm3));
    this->bp.add_r1cs_constraint(r1cs_constraint<FieldT>(score_base + PA_income + interm1 - interm3, 1, score));

    // Check comparison
    this->bp.add_r1cs_constraint(r1cs_constraint<FieldT>(score_min_lte, 1, out));

    digest_PA_id.reset(new digest_variable(this->bp, 256));
    digest_PA_income.reset(new digest_variable(this->bp, 256));
    bits_FI_overdue_loans.reset(new digest_variable(this->bp, 256));
    bits_FI_account_age.reset(new digest_variable(this->bp, 256));

    pa_data_knapsack.reset(new knapsack_field_packing_component<FieldT>(this->bp,
          256 * 2,
          *digest_PA_id,
          *digest_PA_income,
          blueprint_variable_vector<FieldT>(1, PRIV_HASH_PA_data)));
    pa_data_knapsack.get()->generate_r1cs_constraints();

    fi_data_knapsack.reset(new knapsack_field_packing_component<FieldT>(this->bp,
          256 * 2,
          *bits_FI_overdue_loans,
          *bits_FI_account_age,
          blueprint_variable_vector<FieldT>(1, PRIV_HASH_FI_data)));
    fi_data_knapsack.get()->generate_r1cs_constraints();

    this->bp.add_r1cs_constraint(r1cs_constraint<FieldT>(PRIV_HASH_PA_data - PUB_HASH_PA_data, 1, HASH_PA_validation_result));

    this->bp.add_r1cs_constraint(r1cs_constraint<FieldT>(PRIV_HASH_FI_data - PUB_HASH_FI_data, 1, HASH_FI_validation_result));

    std::cout << "Constraints: " << this->bp.num_constraints() << std::endl;
  }



  void generate_r1cs_witness(uint pa_id, uint pa_income, uint fi_overdue_loans, uint fi_account_age, std::string pa_data_hash, std::string fi_data_hash) {

    std::vector<bool> pa_id_bv = uint_to_bitvector(pa_id);
    std::vector<bool> pa_income_bv = uint_to_bitvector(pa_income);

    std::vector<bool> fi_overdue_loans_bv = uint_to_bitvector(fi_overdue_loans);
    std::vector<bool> fi_account_age_bv = uint_to_bitvector(fi_account_age);

    std::vector<bool> pa_data_bv = merge_vectors(pa_id_bv, pa_income_bv);
    std::vector<bool> fi_data_bv = merge_vectors(fi_overdue_loans_bv, fi_account_age_bv);

    digest_PA_id.get()->generate_r1cs_witness(pa_id_bv);
    digest_PA_income.get()->generate_r1cs_witness(pa_income_bv);

    bits_FI_overdue_loans.get()->generate_r1cs_witness(fi_overdue_loans_bv);
    bits_FI_account_age.get()->generate_r1cs_witness(fi_account_age_bv);

    pa_data_knapsack.get()->generate_r1cs_witness();

    // Set private hash of Public Agency data
    value_type _PRIV_HASH_PA_data = knapsack_crh_with_field_out_component<FieldT>::get_hash(pa_data_bv)[0];
    this->bp.val(PRIV_HASH_PA_data) = _PRIV_HASH_PA_data;

    // Set public hash of Public Agency data (public input)
    value_type _PUB_HASH_PA_data = hex_to_field_element(pa_data_hash);
    this->bp.val(PUB_HASH_PA_data) = _PUB_HASH_PA_data;

    // Set private hash of Financial Institution's data
    value_type _PRIV_HASH_FI_data = knapsack_crh_with_field_out_component<FieldT>::get_hash(fi_data_bv)[0];
    this->bp.val(PRIV_HASH_FI_data) = _PRIV_HASH_FI_data;

    // Set public hash of Financial Institution's data (public input)
    value_type _PUB_HASH_FI_data = hex_to_field_element(fi_data_hash);
    this->bp.val(PUB_HASH_FI_data) = _PUB_HASH_FI_data;

    std::cout << "PA data calculated hash: " << field_element_to_hex(_PRIV_HASH_PA_data) << std::endl;
    std::cout << "PA data public hash: " << field_element_to_hex(_PUB_HASH_PA_data) << std::endl;

    std::cout << "FI data calculated hash: " << field_element_to_hex(_PRIV_HASH_FI_data) << std::endl;
    std::cout << "FI data public hash: " << field_element_to_hex(_PUB_HASH_FI_data) << std::endl;
    std::cout << std::endl;

    // ------------------------------------------------------------------------------------------------------
    // ------------------------------------------------------------------------------------------------------

    uint _w_fi_overdue_loans = 10000;
    uint _w_fi_account_age = 5000;
    uint _score_base = 100000;

    uint _interm1 = fi_account_age * _w_fi_account_age;
    uint _interm2 = fi_overdue_loans * fi_overdue_loans;
    uint _interm3 = _interm2 * _w_fi_overdue_loans;
    uint _score = _score_base + pa_income + _interm1 - _interm3;

    /* std::cout << "_w_fi_overdue_loans: " << _w_fi_overdue_loans << std::endl; */
    /* std::cout << "_w_fi_account_age: " << _w_fi_account_age << std::endl; */
    /* std::cout << "_score_base: " << _score_base << std::endl; */

    std::cout << "ID: " << pa_id << std::endl;
    std::cout << "Income: " << pa_income << std::endl;
    std::cout << "Account_age: " << fi_account_age << std::endl;
    std::cout << "Overdue loans: " << fi_overdue_loans << std::endl;
    std::cout << std::endl;

    /* std::cout << "interm1: " << _interm1 << std::endl; */
    /* std::cout << "interm2: " << _interm2 << std::endl; */
    /* std::cout << "interm3: " << _interm3 << std::endl; */

    std::cout << "Score: " << _score << std::endl;

    this->bp.val(interm1) = _interm1;
    this->bp.val(interm2) = _interm2;
    this->bp.val(interm3) = _interm3;

    this->bp.val(score) = _score;

    this->bp.val(score_min) = 70000;

    this->bp.val(score_base) = _score_base;
    this->bp.val(W_FI_overdue_loans) = _w_fi_overdue_loans;
    this->bp.val(W_FI_account_age) = _w_fi_account_age;

    this->bp.val(PA_id) = pa_id;
    this->bp.val(PA_income) = pa_income;
    this->bp.val(FI_overdue_loans) = fi_overdue_loans;
    this->bp.val(FI_account_age) = fi_account_age;

    this->bp.val(HASH_PA_validation_result) = value_type::zero();
    this->bp.val(HASH_FI_validation_result) = value_type::zero();
    this->bp.val(out) = 1;

    score_min_comparator.get()->generate_r1cs_witness();
  }
};
