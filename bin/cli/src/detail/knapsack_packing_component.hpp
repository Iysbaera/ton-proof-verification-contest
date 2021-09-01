#include <nil/crypto3/zk/components/hashes/knapsack/knapsack_component.hpp>
#include <nil/crypto3/zk/components/hashes/hash_io.hpp>

#include <nil/crypto3/zk/components/blueprint.hpp>

using namespace nil::crypto3;
using namespace nil::crypto3::zk;
using namespace nil::crypto3::algebra;
using namespace nil::crypto3::zk::snark;
using namespace components;

template<typename FieldT>
class knapsack_bit_packing_component : public component<FieldT> {
  public:

  std::shared_ptr<knapsack_crh_with_bit_out_component<FieldT>> f;

  knapsack_bit_packing_component(blueprint<FieldT> &bp,
      std::size_t input_len,
      const digest_variable<FieldT> &left,
      const digest_variable<FieldT> &right,
      const digest_variable<FieldT> &output) :
    component<FieldT>(bp) {

      block_variable<FieldT> block(bp, left, right);

      f.reset(new knapsack_crh_with_bit_out_component<FieldT>(
          bp,
          input_len,
          block,
          output));
  }

  void generate_r1cs_constraints() {
      f->generate_r1cs_constraints();
  }

  void generate_r1cs_witness() {
      f->generate_r1cs_witness();
  }
};

template<typename FieldT>
class knapsack_field_packing_component : public component<FieldT> {
  public:

  std::shared_ptr<knapsack_crh_with_field_out_component<FieldT>> f;

  knapsack_field_packing_component(blueprint<FieldT> &bp,
      std::size_t input_len,
      const digest_variable<FieldT> &left,
      const digest_variable<FieldT> &right,
      const blueprint_linear_combination_vector<FieldT> &output) :
    component<FieldT>(bp) {

      block_variable<FieldT> block(bp, left, right);

      f.reset(new knapsack_crh_with_field_out_component<FieldT>(
          bp,
          input_len,
          block,
          output));
  }

  void generate_r1cs_constraints() {
      f->generate_r1cs_constraints();
  }

  void generate_r1cs_witness() {
      f->generate_r1cs_witness();
  }
};
