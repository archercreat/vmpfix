#pragma once
#include <Zydis/Zydis.h>
#include <array>
#include <functional>
#include <mutex>
#include <string>
#include <vector>
#include "image_desc.hpp"

// Why would they remove operands from ZydisDecodedInstruction??? wtf zydis
//
// Can agree, what in the world where they thinking? probably for their
// assembler they had too... (maybe)
struct instruction_t {
  uint64_t runtime_addr;
  ZydisDecodedInstruction i;
  ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];

  uint64_t get_target_addr(size_t n) const;
  bool is_branch() const;
  bool is_jmp() const;
  bool is_call() const;
  bool is_push() const;
  bool is_pop() const;
  std::string to_string() const;
};

using ins_filter_t = std::function<bool(const instruction_t&)>;

// Portion of this code was taken from NoVmp project. Kudos to Can1357
//
struct routine_t {
  std::vector<instruction_t> stream;

  int next(const ins_filter_t& filter, int from = 0) const;
  int prev(const ins_filter_t& filter, int from = -1) const;

  void dump() const;

  auto size() const { return stream.size(); }
  auto begin() { return stream.begin(); }
  auto end() { return stream.end(); }
  auto erase(auto it, auto end) { return stream.erase(it, end); }
  auto operator[](size_t n) const { return stream[n]; }
};

routine_t unroll(image_t* img, uint64_t rva);
bool dis(image_t* img, uint64_t rva, instruction_t* ins);
routine_t deobfuscate(routine_t routine, bool is_64);