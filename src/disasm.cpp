#include "disasm.hpp"
#include <algorithm>
#include <set>

uint64_t instruction_t::get_target_addr(size_t n) const {
  uint64_t out_addr;
  ZydisCalcAbsoluteAddress(&i, &operands[n], runtime_addr, &out_addr);
  return out_addr;
}

bool instruction_t::is_branch() const {
  return i.mnemonic >= ZYDIS_MNEMONIC_JB && i.mnemonic <= ZYDIS_MNEMONIC_JZ;
}

bool instruction_t::is_jmp() const {
  return i.mnemonic == ZYDIS_MNEMONIC_JMP;
}

bool instruction_t::is_call() const {
  return i.mnemonic == ZYDIS_MNEMONIC_CALL &&
         operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE;
}

bool instruction_t::is_push() const {
  return i.mnemonic == ZYDIS_MNEMONIC_PUSH &&
         operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER;
}

bool instruction_t::is_pop() const {
  return i.mnemonic == ZYDIS_MNEMONIC_POP &&
         operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER;
}

std::string instruction_t::to_string() const {
  char buffer[80];
  ZydisFormatter formatter;
  ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);
  ZydisFormatterFormatInstruction(&formatter, &i, operands,
                                  i.operand_count_visible, buffer,
                                  sizeof(buffer), runtime_addr);
  return {buffer};
}

int routine_t::next(const ins_filter_t& filter, int from) const {
  if (from >= stream.size())
    return -1;
  for (int i = from; i < stream.size(); i++)
    if (filter(stream[i]))
      return i;
  return -1;
}

int routine_t::prev(const ins_filter_t& filter, int from) const {
  if (from == -1)
    from = (int)stream.size() - 1;
  if (from >= stream.size())
    return -1;
  for (int i = from; i >= 0; i--)
    if (filter(stream[i]))
      return i;
  return -1;
}

void routine_t::dump() const {
  for (const auto& ins : stream)
    std::printf("[*] 0x%llx %s\n", ins.runtime_addr, ins.to_string().c_str());
}

routine_t unroll(image_t* img, uint64_t rva) {
  routine_t routine;
  ZydisDecoder decoder;
  ZydisDecoderInit(
      &decoder,
      img->is_64() ? ZYDIS_MACHINE_MODE_LONG_64 : ZYDIS_MACHINE_MODE_LEGACY_32,
      img->is_64() ? ZYDIS_STACK_WIDTH_64 : ZYDIS_STACK_WIDTH_32);

  ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
  ZydisDecodedInstruction i;

  while (ZYAN_SUCCESS(ZydisDecoderDecodeFull(
      &decoder, img->raw_to_ptr((uint32_t)rva), ZYDIS_MAX_INSTRUCTION_LENGTH,
      &i, operands, ZYDIS_MAX_OPERAND_COUNT, 0))) {
    instruction_t ins;
    ins.runtime_addr = rva + img->get_mapped_image_base();
    ins.i = i;
    std::copy(std::begin(operands), std::end(operands),
              std::begin(ins.operands));

    // Exit if we found a loop.
    //
    if (std::any_of(routine.begin(), routine.end(), [&](const auto& i) {
          return i.runtime_addr == ins.runtime_addr;
        }))
      return routine;

    if (ins.is_jmp() || ins.is_branch()) {
      if (ins.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER) {
        routine.stream.push_back(ins);
        return routine;
      }

      if (rva = ins.get_target_addr(0); img->has_va(rva))
        rva -= img->get_mapped_image_base();
      else {
        routine.stream.push_back(ins);
        return routine;
      }
    } else if (ins.i.mnemonic == ZYDIS_MNEMONIC_RET ||
               ins.i.mnemonic == ZYDIS_MNEMONIC_CALL) {
      routine.stream.push_back(ins);
      return routine;
    } else {
      routine.stream.push_back(ins);
      rva += ins.i.length;
    }
  }
  return routine;
}

bool dis(image_t* img, uint64_t rva, instruction_t* ins) {
  std::memset(ins, 0, sizeof(instruction_t));
  ZydisDecoder decoder;
  ZydisDecoderInit(
      &decoder,
      img->is_64() ? ZYDIS_MACHINE_MODE_LONG_64 : ZYDIS_MACHINE_MODE_LEGACY_32,
      img->is_64() ? ZYDIS_STACK_WIDTH_64 : ZYDIS_STACK_WIDTH_32);

  ins->runtime_addr = rva + img->get_mapped_image_base();
  return ZYAN_SUCCESS(ZydisDecoderDecodeFull(
      &decoder, img->raw_to_ptr((uint32_t)rva), ZYDIS_MAX_INSTRUCTION_LENGTH,
      &ins->i, ins->operands, ZYDIS_MAX_OPERAND_COUNT, 0));
}

// l33t deobfuscation
// powerful indeed...
routine_t deobfuscate(routine_t routine, bool is_64) {
  const std::set valid_instructions = {
      ZYDIS_MNEMONIC_PUSH, ZYDIS_MNEMONIC_POP,  ZYDIS_MNEMONIC_LEA,
      ZYDIS_MNEMONIC_MOV,  ZYDIS_MNEMONIC_XCHG, ZYDIS_MNEMONIC_RET,
  };
  std::set valid_registers = {
      ZYDIS_REGISTER_RAX, ZYDIS_REGISTER_RBX, ZYDIS_REGISTER_RCX,
      ZYDIS_REGISTER_RDX, ZYDIS_REGISTER_RDI, ZYDIS_REGISTER_RSI,
      ZYDIS_REGISTER_RBP, ZYDIS_REGISTER_RSP, ZYDIS_REGISTER_R8,
      ZYDIS_REGISTER_R9,  ZYDIS_REGISTER_R10, ZYDIS_REGISTER_R11,
      ZYDIS_REGISTER_R12, ZYDIS_REGISTER_R13, ZYDIS_REGISTER_R14,
      ZYDIS_REGISTER_R15,
  };
  if (!is_64) {
    valid_registers.insert({
        ZYDIS_REGISTER_EAX,
        ZYDIS_REGISTER_EBX,
        ZYDIS_REGISTER_ECX,
        ZYDIS_REGISTER_EDX,
        ZYDIS_REGISTER_ESI,
        ZYDIS_REGISTER_EDI,
        ZYDIS_REGISTER_EBP,
        ZYDIS_REGISTER_ESP,
    });
  }

  routine.erase(
      std::remove_if(
          routine.begin(), routine.end(),
          [&](const instruction_t& ins) {
            return valid_instructions.find(ins.i.mnemonic) ==
                       valid_instructions.end() ||
                   std::any_of(
                       std::begin(ins.operands), std::end(ins.operands),
                       [&](const ZydisDecodedOperand& operand) {
                         if (operand.type == ZYDIS_OPERAND_TYPE_REGISTER &&
                             operand.visibility ==
                                 ZYDIS_OPERAND_VISIBILITY_EXPLICIT)
                           return valid_registers.find(operand.reg.value) ==
                                  valid_registers.end();
                         return false;
                       });
          }),
      routine.end());

  return routine;
}
