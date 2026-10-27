// Unbounded recursion runs into the stack guard page: EXC_BAD_ACCESS / SIGSEGV.

__attribute__((noinline)) static int descend(int n) {
    volatile char pad[256];
    pad[0] = (char)n;
    return descend(n + 1) + pad[0];
}

int main(void) {
    return descend(0);
}
