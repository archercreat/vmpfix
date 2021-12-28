#include <optional>
#include <set>
#include <stdexcept>

#include "disasm.hpp"
#include "vmp_analyzer.hpp"

static std::set<std::string_view> vmp_names;

inline static constexpr void abort_if(bool cond,
                                      const char* message = nullptr) {
  if (cond)
    throw std::runtime_error(message);
}

std::string vmp_stub_t::to_string() const {
  const auto name = type == stub_type_t::move   ? "mov  "
                    : type == stub_type_t::call ? "call"
                                                : "jmp ";
  const auto op = type == stub_type_t::move
                      ? ZydisRegisterGetString((ZydisRegister)output_reg)
                      : "";
  char buff[256];

  std::snprintf(buff, 256, "[%lld] 0x%llx %s %s 0x%llx", ins_size, ins_address,
                name, op, resolved_api);
  return {buff};
}

// AFAIK VMProtect patches only 3 types of instructions: call, jmp and mov.
// The later is only available on x86 and mostly missed by other projects.
//
vmp_stub_t analyze_stub(const instruction_t& last_ins,
                        const instruction_t& call_ins,
                        routine_t& routine) {
  vmp_stub_t out;
  // Example:
  // > 0x7ff7bbc4e538 pop rdx
  // > 0x7ff7bbc2a4e3 xchg [rsp], rdx
  // > 0x7ff7bbc1540a push rdx
  // > 0x7ff7bbc54044 lea rdx, [0x00007FF7BB81E398]
  // > 0x7ff7bbc5404b mov rdx, [rdx+0x43428C]
  // > 0x7ff7bbc102c1 lea rdx, [rdx+0x39E75B2B]
  // > 0x7ff7bbc4592c xchg [rsp], rdx
  // > 0x7ff7bbc20638 ret 0x08
  //
  // Calculate stack displacement.
  //
  int n_pops = 0, n_pushes = 0;
  for (const auto& ins : routine) {
    if (ins.i.mnemonic == ZYDIS_MNEMONIC_PUSH)
      n_pushes++;
    if (ins.i.mnemonic == ZYDIS_MNEMONIC_POP)
      n_pops++;
  }
  int stack_disp = n_pops - n_pushes;

  // Find lea increment.
  //
  auto lea_inc = routine.next([](const instruction_t& ins) {
    return ins.i.mnemonic == ZYDIS_MNEMONIC_LEA &&
           ins.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
           ins.operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY &&
           ins.operands[1].mem.disp.value > 0 &&
           ins.operands[1].mem.disp.value < 3 &&
           ins.operands[1].mem.base == ins.operands[0].reg.value;
  });
  uint64_t lea_inc_v =
      (lea_inc == -1 ? 0 : routine[lea_inc].operands[1].mem.disp.value);

  // All jump stubs end with `ret 4/8`.
  //
  if (routine[routine.size() - 1].i.length == 3) {
    out.type = stub_type_t::jump;
    auto has_pop = routine.prev(
        [](const auto& ins) { return ins.i.mnemonic == ZYDIS_MNEMONIC_POP; },
        2);
    if (has_pop != -1)
      abort_if(last_ins.i.mnemonic != ZYDIS_MNEMONIC_PUSH);
    out.ins_address =
        has_pop != -1 ? last_ins.runtime_addr : call_ins.runtime_addr;
    out.ins_size = has_pop != -1 ? last_ins.i.length + call_ins.i.length : 6;
  }
  // All call stubs end with `xchg`.
  //
  else if (routine[routine.size() - 2].i.mnemonic == ZYDIS_MNEMONIC_XCHG) {
    out.type = stub_type_t::call;

    if (stack_disp == -1) {
      // Make sure lea increment is present.
      //
      abort_if(lea_inc == -1);
      out.ins_size = call_ins.i.length + lea_inc_v;
      out.ins_address = call_ins.runtime_addr;
    } else if (stack_disp == 0) {
      // Make sure no lea increment is present and last instruction before the
      // call is `push`.
      //
      abort_if(lea_inc != -1);
      abort_if(last_ins.i.mnemonic != ZYDIS_MNEMONIC_PUSH);
      out.ins_size = last_ins.i.length + call_ins.i.length;
      out.ins_address = last_ins.runtime_addr;
    } else
      abort_if(true, "Invalid displacement. Should never happen");
  }
  // Everything else should be considered as `mov`.
  //
  else {
    out.type = stub_type_t::move;
    // Get output register.
    // There are 2 cases:
    // mov out_reg, reg
    // pop reg
    // ret
    //
    // lea out_reg, [out_reg + imm]
    // ret
    //
    auto assign = routine.next(
        [&](const instruction_t& ins) {
          return ins.i.mnemonic == ZYDIS_MNEMONIC_MOV &&
                 ins.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                 ins.operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER;
        },
        (int)routine.size() - 4);

    auto lea = routine.next(
        [&](const instruction_t& ins) {
          return ins.i.mnemonic == ZYDIS_MNEMONIC_LEA &&
                 ins.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                 ins.operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY;
        },
        (int)routine.size() - 4);

    abort_if(assign != -1 && lea != -1);
    // Get output register.
    //
    out.output_reg = assign != -1 ? routine[assign].operands[0].reg.value
                                  : routine[lea].operands[0].reg.value;

    if (stack_disp == 1) {
      abort_if(last_ins.i.mnemonic != ZYDIS_MNEMONIC_PUSH);
      out.ins_size = last_ins.i.length + call_ins.i.length + lea_inc_v;
      out.ins_address = last_ins.runtime_addr;
    } else if (stack_disp == 0) {
      out.ins_size = call_ins.i.length + lea_inc_v;
      out.ins_address = call_ins.runtime_addr;
    } else if (stack_disp == -1) {
      abort_if(last_ins.i.mnemonic != ZYDIS_MNEMONIC_POP);
      out.ins_size = last_ins.i.length + call_ins.i.length + lea_inc_v;
      out.ins_address = last_ins.runtime_addr;
    } else
      abort_if(true, "Invalid displacement. Should never happen");
  }
  return out;
}

// Resolving stub must have exactly 3 instructions:
// `lea reg, [imm]` or `mov reg, imm`
// `mov reg, [reg + imm]`
// `lea reg, [reg + imm]`
//
static std::optional<uint64_t> resolve_api(image_t* img,
                                           const routine_t& routine) {
  int from = (int)routine.size() - 1;

  while (from != -1) {
    // Match `lea reg, [imm]` or `mov reg, imm`.
    //
    auto assign = routine.prev(
        [&](const instruction_t& ins) {
          return img->is_64()
                     ? (ins.i.mnemonic == ZYDIS_MNEMONIC_LEA &&
                        ins.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                        ins.operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                        ins.operands[1].mem.base == ZYDIS_REGISTER_RIP &&
                        ins.operands[1].mem.index == ZYDIS_REGISTER_NONE)
                     : (ins.i.mnemonic == ZYDIS_MNEMONIC_MOV &&
                        ins.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                        ins.operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE);
        },
        from - 1);

    if (assign == -1)
      return {};
    from = assign;

    // Extract initial value and output register.
    //
    const auto output_r = routine[assign].operands[0].reg.value;
    auto value = img->is_64() ? routine[assign].get_target_addr(1)
                              : routine[assign].operands[1].imm.value.u;

    // Match `mov reg, [reg + imm]`.
    //
    auto mem = routine.next(
        [&](const instruction_t& ins) {
          return ins.i.mnemonic == ZYDIS_MNEMONIC_MOV &&
                 ins.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                 ins.operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                 ins.operands[1].mem.base == output_r;
        },
        assign);
    // Try again.
    //
    if (mem == -1)
      continue;
    // Compute memory rva.
    //
    uint64_t mem_rva = (routine[mem].operands[1].mem.disp.value + value) -
                       img->get_mapped_image_base();
    // Read value from image.
    //
    if (img->is_64())
      value = *img->raw_to_ptr<uint64_t>((uint32_t)mem_rva);
    else
      value = *img->raw_to_ptr<uint32_t>((uint32_t)mem_rva);
    // Match `lea reg, [reg + imm]`.
    //
    auto add = routine.next(
        [&](const instruction_t& ins) {
          return ins.i.mnemonic == ZYDIS_MNEMONIC_LEA &&
                 ins.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                 ins.operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                 ins.operands[1].mem.base == output_r;
        },
        mem);
    // Try again.
    //
    if (add == -1)
      continue;
    // Compute last displacement.
    //
    value = value + routine[add].operands[1].mem.disp.value;
    return img->is_64() ? value : value & 0xffffffff;
  }
  return {};
}

static std::vector<vmp_stub_t> analyze_section(image_t* img, size_t n) {
  std::vector<vmp_stub_t> stubs;
  auto* sec = img->get_nt_headers()->get_section(n);
  // Process executale non VMP sections only.
  //
  if (!sec->characteristics.mem_execute ||
      vmp_names.find(sec->name.to_string()) != vmp_names.end())
    return {};

  auto start_rva = sec->virtual_address;
  auto end_rva = sec->virtual_address + sec->virtual_size;

  while (start_rva + 5 < end_rva) {
    instruction_t ins;
    const auto raw = img->raw_to_ptr(start_rva);
    // We are looking for calls to vmp section.
    //
    if (*raw == 0xe8 && dis(img, start_rva, &ins) &&
        img->has_va(ins.get_target_addr(0))) {
      const auto target_rva = static_cast<uint32_t>(
          ins.get_target_addr(0) - img->get_mapped_image_base());
      const auto sec = img->rva_to_section(target_rva);
      if (sec && vmp_names.find(sec->name.to_string()) != vmp_names.end()) {
        auto ss = deobfuscate(unroll(img, target_rva), img->is_64());
        if (ss.size() > 3 && ss.size() < 20) {
          const auto api = resolve_api(img, ss);
          if (!api.has_value()) {
            std::printf("Failed to resolve api at 0x%llx\n", ins.runtime_addr);
            ss.dump();
          } else {
            // Try to get instruction before the call. We are looking for push
            // and pop instructions. We don't care if `dis` will fail here.
            //
            instruction_t b_ins;
            dis(img, start_rva - 1, &b_ins);

            auto stub = analyze_stub(b_ins, ins, ss);
            stub.resolved_api = api.value();
            start_rva = static_cast<uint32_t>(stub.ins_address + stub.ins_size -
                                              img->get_mapped_image_base());
            stubs.push_back(std::move(stub));
            continue;
          }
        }
      }
    }
    start_rva++;
  }
  return stubs;
}

void init_section_names(const std::vector<std::string>& names) {
  vmp_names.insert(names.begin(), names.end());
}

std::vector<vmp_stub_t> collect_stubs(image_t* img) {
  std::vector<vmp_stub_t> out;
  for (int i = 0; i < img->get_nt_headers()->file_header.num_sections; i++) {
    auto stubs = analyze_section(img, i);
    out.insert(out.end(), stubs.begin(), stubs.end());
  }
  return out;
}

// Given vmp_stub_t and iat address, encode original instruction and return raw
// bytes.
//
std::vector<uint8_t> encode_stub(const vmp_stub_t& stub,
                                 uint64_t iat,
                                 bool is_64) {
  std::vector<uint8_t> out;
  out.resize(ZYDIS_MAX_INSTRUCTION_LENGTH);

  // Initialize Encoder.
  //
  ZydisEncoderRequest req;
  std::memset(&req, 0, sizeof(req));
  req.machine_mode =
      is_64 ? ZYDIS_MACHINE_MODE_LONG_64 : ZYDIS_MACHINE_MODE_LEGACY_32;

  // This function is only needed on x64 targets because memory accesses are rip
  // relative. Since VMP supports only call/jmp on x64, the instuction size is
  // always 6.
  //
  auto calc_relative_addr = [&]() -> uint64_t {
    return iat - stub.ins_address - 6;
  };

  auto encode_api = [&](ZydisEncoderOperand* op) {
    op->type = ZYDIS_OPERAND_TYPE_MEMORY;
    op->mem.displacement = is_64 ? calc_relative_addr() : iat;
    op->mem.base = is_64 ? ZYDIS_REGISTER_RIP : ZYDIS_REGISTER_NONE;
    op->mem.size = is_64 ? 8 : 4;
  };
  // Encode `lea reg, [IAT]` on x64 or `mov reg, [IAT]` on x86.
  //
  auto encode_lea = [&]() {
    req.mnemonic = is_64 ? ZYDIS_MNEMONIC_LEA : ZYDIS_MNEMONIC_MOV;
    req.operand_count = 2;
    req.operands[0].type = ZYDIS_OPERAND_TYPE_REGISTER;
    req.operands[0].reg.value = (ZydisRegister)stub.output_reg;
    encode_api(&req.operands[1]);
  };
  // Encode `jmp [IAT]`.
  //
  auto encode_jmp = [&]() {
    req.mnemonic = ZYDIS_MNEMONIC_JMP;
    req.operand_count = 1;
    encode_api(&req.operands[0]);
  };
  // Encode `call [IAT]`.
  //
  auto encode_call = [&]() {
    req.mnemonic = ZYDIS_MNEMONIC_CALL;
    req.operand_count = 1;
    encode_api(&req.operands[0]);
  };

  if (stub.type == stub_type_t::move)
    encode_lea();
  if (stub.type == stub_type_t::call)
    encode_call();
  if (stub.type == stub_type_t::jump)
    encode_jmp();

  size_t encoded_len = out.size();
  abort_if(!ZYAN_SUCCESS(
      ZydisEncoderEncodeInstruction(&req, out.data(), &encoded_len)));
  // Resize to instruction length.
  //
  out.resize(encoded_len);
  return out;
}
