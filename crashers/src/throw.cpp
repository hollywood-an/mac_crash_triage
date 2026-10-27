// Uncaught C++ exception: std::terminate -> abort() -> EXC_CRASH / SIGABRT.
#include <stdexcept>

__attribute__((noinline)) static void load_config(const char *path) {
    (void)path;
    throw std::runtime_error("config file not found");
}

int main() {
    load_config("missing.conf");
    return 0;
}
