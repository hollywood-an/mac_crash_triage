// Write to a read-only code page: EXC_BAD_ACCESS / SIGBUS (KERN_PROTECTION_FAILURE).
#include <stdint.h>

__attribute__((noinline)) static void target(void) {}

__attribute__((noinline)) static void patch_code(volatile uint32_t *insn) {
    *insn = 0xd503201f; // arm64 NOP
}

int main(void) {
    patch_code((volatile uint32_t *)(uintptr_t)&target);
    return 0;
}
