// __builtin_trap compiles to `brk #1` on arm64: EXC_BREAKPOINT / SIGTRAP.

__attribute__((noinline)) static int checked_div(int a, int b) {
    if (b == 0) {
        __builtin_trap();
    }
    return a / b;
}

int main(int argc, char **argv) {
    (void)argv;
    return checked_div(10, argc - 1); // argc is 1 when run without arguments
}
