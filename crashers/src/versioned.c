// One bug shipped in two versions. VERSION 2 adds code above the faulting
// function, so every image offset moves while the function names stay the same.
// The fingerprint must put both versions in one cluster.
#include <stdio.h>
#include <string.h>

#ifndef VERSION
#define VERSION 1
#endif

struct record {
    const char *name;
    int len;
};

#if VERSION >= 2
__attribute__((noinline)) static int validate(const char *s) {
    return s != NULL && strlen(s) < 64;
}
#endif

// The bug: lookup() can return NULL and parse_record() does not check.
__attribute__((noinline)) static int parse_record(const struct record *r) {
    return r->name[0] == '#';
}

__attribute__((noinline)) static const struct record *lookup(int key) {
    (void)key;
    return NULL;
}

__attribute__((noinline)) static int handle_request(int key) {
#if VERSION >= 2
    if (!validate("request")) {
        return -1;
    }
#endif
    return parse_record(lookup(key));
}

int main(int argc, char **argv) {
    (void)argv;
    printf("crasher version %d\n", VERSION);
    return handle_request(argc);
}
