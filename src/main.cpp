#include <BlackBone/Process/Process.h>
#include <argparse/argparse.hpp>
#include "vmp_analyzer.hpp"

using namespace blackbone;

int main(int argc, char** argv) {
  argparse::ArgumentParser program("Universal VMProtect Import fixer");

  program.add_argument("-p", "--pid")
      .help("Target process id")
      .required()
      .scan<'i', int>();

  program.add_argument("-s", "--sections")
      .help("VMProtect sections in target module")
      .default_value<std::vector<std::string>>(
          {".vmp0", ".vmp1", ".be1", ".be0"})
      .append();

  program.add_argument("-i", "--iat")
      .help("New IAT section name")
      .default_value<std::string>(".vmp0");

  program.add_argument("-m", "--module")
      .help("VMProtected module name (default: main executable)")
      .default_value<std::string>("");

  try {
    program.parse_args(argc, argv);
  } catch (const std::runtime_error& err) {
    std::cerr << err.what() << std::endl;
    std::cerr << program;
    std::exit(1);
  }

  auto pid = program.get<int>("--pid");
  auto secs = program.get<std::vector<std::string>>("--sections");
  auto iat_name = program.get<std::string>("--iat");
  auto mod_name = program.get<std::string>("--module");

  if (Process proc; NT_SUCCESS(proc.Attach(pid))) {
    auto& memory = proc.memory();
    auto& modules = proc.modules();
    auto target_m =
        mod_name == ""
            ? modules.GetMainModule()
            : modules.GetModule(std::wstring(mod_name.begin(), mod_name.end()));

    if (!target_m) {
      std::cout << "Failed to find module \"" << mod_name << "\" in process"
                << std::endl;
      std::exit(1);
    }

    auto img = std::make_shared<image_t>();
    img->raw.resize(target_m->size);
    img->mapped_image_base = target_m->baseAddress;
    // Read whole module.
    //
    memory.Read(target_m->baseAddress, target_m->size, img->raw.data());

    init_section_names(secs);

    std::cout << "Collecting stubs on " << mod_name << std::endl;

    auto stubs = collect_stubs(img.get());
    std::printf("Found %llu protected imports\n", stubs.size());

    for (const auto& sec : img->get_nt_headers()->sections()) {
      if (sec.name.equals(iat_name.c_str())) {
        // Sort imports by module. This is needed to reduce size of import
        // directory.
        //
        std::map<ModuleDataPtr, std::vector<vmp_stub_t>> modmap;
        // Fill modules.
        //
        for (const auto& [_, data] : modules.GetAllModules())
          modmap[data] = {};

        for (const auto& stub : stubs) {
          if (std::none_of(modmap.begin(), modmap.end(), [&](auto& it) {
                auto& [module, imports] = it;
                if (module->baseAddress <= stub.resolved_api &&
                    stub.resolved_api < module->baseAddress + module->size) {
                  imports.push_back(stub);
                  return true;
                }
                return false;
              })) {
            std::printf("Failed to find 0x%llx in loaded modules\n",
                        stub.resolved_api);
          }
        }

        const auto ptrsize = img->is_64() ? 8 : 4;
        uint64_t iat_base = sec.virtual_address + img->get_mapped_image_base();
        uint64_t off = 0;
        std::cout << "New IAT: 0x" << std::hex << iat_base << std::endl;

        std::unordered_map<uint64_t, uint64_t> iat;
        // Patch instructions.
        //
        for (const auto& [module, imports] : modmap) {
          std::wcout << L"Processing " << module->name << std::endl;
          for (const auto& stub : imports) {
            uint64_t import_addr = 0;
            if (iat.find(stub.resolved_api) != iat.end())
              import_addr = iat.at(stub.resolved_api);
            else {
              memory.Write(iat_base + off, ptrsize, &stub.resolved_api);
              iat[stub.resolved_api] = iat_base + off;
              import_addr = iat_base + off;
              off += ptrsize;
            }

            const auto& raw = encode_stub(stub, import_addr, img->is_64());
            memory.Write(stub.ins_address, raw.size(), raw.data());
            std::cout << "Patched: " << stub.to_string() << std::endl;
          }
        }
      }
    }
  } else
    std::cout << "Failed to attach to " << pid << std::endl;
}
