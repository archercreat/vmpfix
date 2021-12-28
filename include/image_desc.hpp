#pragma once
#include <linuxpe>
#include <vector>

struct image_t {
  std::vector<uint8_t> raw;
  uint64_t mapped_image_base = 0;

  auto get_pe_header() -> win::image_x64_t* {
    return (win::image_x64_t*)raw.data();
  }
  auto get_nt_headers() -> win::nt_headers_x64_t* {
    return get_pe_header()->get_nt_headers();
  }
  auto get_mapped_image_base() -> uint64_t {
    return mapped_image_base ? mapped_image_base
                             : get_nt_headers()->optional_header.image_base;
  }
  inline auto is_64() -> bool {
    return get_nt_headers()->optional_header.magic == 0x20b;
  }
  auto has_va(uint64_t va) -> bool {
    return get_mapped_image_base() <= va &&
           va < (get_mapped_image_base() + raw.size());
  }

  auto rva_to_section(uint32_t rva) -> win::section_header_t* {
    return get_pe_header()->rva_to_section(rva);
  }
  template <typename T = uint8_t>
  T* raw_to_ptr(uint32_t rva) {
    return get_pe_header()->raw_to_ptr<T>(rva);
  }
};
