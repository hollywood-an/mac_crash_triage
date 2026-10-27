// Null pointer write: EXC_BAD_ACCESS / SIGSEGV (KERN_INVALID_ADDRESS).
#include <stddef.h>

struct record {
    int id;
    char name[16];
};

__attribute__((noinline)) static void store_id(struct record *r, int id) {
    r->id = id;
}

int main(void) {
    struct record *volatile r = NULL;
    store_id(r, 42);
    return 0;
}
