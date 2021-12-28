#pragma once
#include <linuxpe>
#include <vector>

#include "image_desc.hpp"

enum class stub_type_t { jump, call, move };

struct vmp_stub_t {
  stub_type_t type;
  // Address of resolved api.
  //
  uint64_t resolved_api;
  // Address of original call/jmp/mov instuction.
  //
  uint64_t ins_address;
  // Original instruction size.
  //
  uint64_t ins_size;
  // In case of `lea` output reg is filled by Zydis.
  //
  uint64_t output_reg;

  std::string to_string() const;
};

void init_section_names(const std::vector<std::string>& names);
std::vector<vmp_stub_t> collect_stubs(image_t* img);
std::vector<uint8_t> encode_stub(const vmp_stub_t& stub,
                                 uint64_t iat,
                                 bool is_64);