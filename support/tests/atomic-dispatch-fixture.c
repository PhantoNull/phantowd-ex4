/* SPDX-License-Identifier: Apache-2.0
 * SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
 * Memory-only disposable guest test, never installed in the product.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <grp.h>
#include <inttypes.h>
#include <linux/capability.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#define LIBRARY "/lib/libatomic.so.1.2.0"
#define CHECK(condition) do { if (!(condition)) { \
    fputs("PHANTOWD_ATOMIC_FAILED\n", stderr); exit(1); } } while (0)

static void *library;

static void drop_privileges(void)
{
    struct __user_cap_header_struct header = {
        .version = _LINUX_CAPABILITY_VERSION_3, .pid = 0
    };
    struct __user_cap_data_struct caps[2] = {{0}, {0}};
    CHECK(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0);
    CHECK(setgroups(0, NULL) == 0);
    CHECK(setgid(1000) == 0 && setuid(1000) == 0);
    CHECK(getuid() == 1000 && geteuid() == 1000);
    CHECK(getgid() == 1000 && getegid() == 1000);
    CHECK(getgroups(0, NULL) == 0);
    CHECK(syscall(SYS_capget, &header, caps) == 0);
    CHECK(caps[0].effective == 0 && caps[1].effective == 0);
    CHECK(caps[0].permitted == 0 && caps[1].permitted == 0);
    CHECK(caps[0].inheritable == 0 && caps[1].inheritable == 0);
    CHECK(prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) == 1);
}

static void *resolve(const char *name)
{
    Dl_info info;
    void *address;
    dlerror();
    address = dlvsym(library, name, "LIBATOMIC_1.0");
    CHECK(dlerror() == NULL && address != NULL);
    CHECK(dladdr(address, &info) != 0);
    CHECK(info.dli_fname != NULL && strcmp(info.dli_fname, LIBRARY) == 0);
    CHECK((uintptr_t)address >= (uintptr_t)info.dli_fbase);
    printf("PHANTOWD_ATOMIC_SYMBOL name=%s offset=%" PRIxPTR "\n",
           name, (uintptr_t)address - (uintptr_t)info.dli_fbase);
    return address;
}

/* dlvsym forces calls through the actual exported library implementation,
 * rather than allowing the compiler to inline atomic builtins. */
#define RESOLVE(variable, operation, width) do { \
    void *address = resolve("__atomic_" operation "_" #width); \
    _Static_assert(sizeof(variable) == sizeof(address), "pointer width"); \
    memcpy(&(variable), &address, sizeof(variable)); \
} while (0)

#define DEFINE_TEST(T, N) \
static T (*load_##N)(const volatile void *, int); \
static void (*store_##N)(volatile void *, T, int); \
static T (*exchange_##N)(volatile void *, T, int); \
static bool (*cas_##N)(volatile void *, void *, T, int, int); \
static T (*add_##N)(volatile void *, T, int); \
static T (*sub_##N)(volatile void *, T, int); \
static T (*and_##N)(volatile void *, T, int); \
static T (*or_##N)(volatile void *, T, int); \
static T (*xor_##N)(volatile void *, T, int); \
static struct { T cells[8]; } state_##N __attribute__((aligned(8))); \
static void *increment_##N(void *unused) \
{ \
    (void)unused; \
    for (unsigned i = 0; i < 2000; ++i) \
        (void)add_##N(&state_##N.cells[2], (T)1, __ATOMIC_SEQ_CST); \
    return NULL; \
} \
static void test_##N(void) \
{ \
    const int loads[] = {__ATOMIC_RELAXED, __ATOMIC_ACQUIRE, __ATOMIC_SEQ_CST}; \
    const int stores[] = {__ATOMIC_RELAXED, __ATOMIC_RELEASE, __ATOMIC_SEQ_CST}; \
    const int rmw[] = {__ATOMIC_RELAXED, __ATOMIC_ACQUIRE, __ATOMIC_RELEASE, \
                       __ATOMIC_ACQ_REL, __ATOMIC_SEQ_CST}; \
    T *value = &state_##N.cells[2]; \
    T seed = (T)UINT64_C(0x1234567887654321); \
    T replacement = (T)UINT64_C(0x9876543212345678); \
    T mismatch = N == 8 ? (T)UINT64_C(0x100000000) : (T)1; \
    T maximum = (T)~(T)0; \
    pthread_t threads[2]; \
    RESOLVE(load_##N, "load", N); \
    RESOLVE(store_##N, "store", N); \
    RESOLVE(exchange_##N, "exchange", N); \
    RESOLVE(cas_##N, "compare_exchange", N); \
    RESOLVE(add_##N, "fetch_add", N); \
    RESOLVE(sub_##N, "fetch_sub", N); \
    RESOLVE(and_##N, "fetch_and", N); \
    RESOLVE(or_##N, "fetch_or", N); \
    RESOLVE(xor_##N, "fetch_xor", N); \
    for (unsigned i = 0; i < 8; ++i) state_##N.cells[i] = (T)0xa5; \
    *value = (T)7; \
    for (unsigned i = 0; i < 3; ++i) CHECK(load_##N(value, loads[i]) == (T)7); \
    for (unsigned i = 0; i < 3; ++i) { \
        store_##N(value, (T)(10 + i), stores[i]); \
        CHECK(load_##N(value, __ATOMIC_SEQ_CST) == (T)(10 + i)); \
    } \
    for (unsigned i = 0; i < 5; ++i) { \
        T expected; \
        int failure = rmw[i] == __ATOMIC_RELEASE ? __ATOMIC_RELAXED : \
                      rmw[i] == __ATOMIC_ACQ_REL ? __ATOMIC_ACQUIRE : rmw[i]; \
        store_##N(value, (T)9, __ATOMIC_SEQ_CST); \
        CHECK(exchange_##N(value, (T)21, rmw[i]) == (T)9); \
        CHECK(load_##N(value, __ATOMIC_SEQ_CST) == (T)21); \
        expected = (T)21; \
        CHECK(cas_##N(value, &expected, (T)35, rmw[i], failure)); \
        CHECK(expected == (T)21 && load_##N(value, __ATOMIC_SEQ_CST) == (T)35); \
        expected = (T)22; \
        CHECK(!cas_##N(value, &expected, (T)99, rmw[i], failure)); \
        CHECK(expected == (T)35 && load_##N(value, __ATOMIC_SEQ_CST) == (T)35); \
        CHECK(add_##N(value, (T)8, rmw[i]) == (T)35); \
        CHECK(load_##N(value, __ATOMIC_SEQ_CST) == (T)43); \
        CHECK(sub_##N(value, (T)3, rmw[i]) == (T)43); \
        CHECK(load_##N(value, __ATOMIC_SEQ_CST) == (T)40); \
        CHECK(and_##N(value, (T)31, rmw[i]) == (T)40); \
        CHECK(load_##N(value, __ATOMIC_SEQ_CST) == (T)8); \
        CHECK(or_##N(value, (T)16, rmw[i]) == (T)8); \
        CHECK(load_##N(value, __ATOMIC_SEQ_CST) == (T)24); \
        CHECK(xor_##N(value, (T)3, rmw[i]) == (T)24); \
        CHECK(load_##N(value, __ATOMIC_SEQ_CST) == (T)27); \
    } \
    store_##N(value, seed, __ATOMIC_SEQ_CST); \
    T expected = seed; \
    CHECK(cas_##N(value, &expected, replacement, __ATOMIC_SEQ_CST, \
                  __ATOMIC_SEQ_CST)); \
    CHECK(expected == seed && load_##N(value, __ATOMIC_SEQ_CST) == replacement); \
    expected = replacement ^ mismatch; \
    CHECK(!cas_##N(value, &expected, seed, __ATOMIC_SEQ_CST, \
                   __ATOMIC_SEQ_CST)); \
    CHECK(expected == replacement); \
    CHECK(load_##N(value, __ATOMIC_SEQ_CST) == replacement); \
    store_##N(value, maximum, __ATOMIC_SEQ_CST); \
    CHECK(add_##N(value, (T)1, __ATOMIC_SEQ_CST) == maximum); \
    CHECK(load_##N(value, __ATOMIC_SEQ_CST) == (T)0); \
    CHECK(sub_##N(value, (T)1, __ATOMIC_SEQ_CST) == (T)0); \
    CHECK(load_##N(value, __ATOMIC_SEQ_CST) == maximum); \
    store_##N(value, (T)0, __ATOMIC_SEQ_CST); \
    CHECK(pthread_create(&threads[0], NULL, increment_##N, NULL) == 0); \
    CHECK(pthread_create(&threads[1], NULL, increment_##N, NULL) == 0); \
    CHECK(pthread_join(threads[0], NULL) == 0); \
    CHECK(pthread_join(threads[1], NULL) == 0); \
    CHECK(load_##N(value, __ATOMIC_SEQ_CST) == (T)4000); \
    for (unsigned i = 0; i < 8; ++i) \
        if (i != 2) CHECK(state_##N.cells[i] == (T)0xa5); \
    printf("PHANTOWD_ATOMIC_WIDTH bytes=%u scenarios=50 increments=4000 guards=unchanged\n", (unsigned)N); \
}

DEFINE_TEST(uint8_t, 1)
DEFINE_TEST(uint16_t, 2)
DEFINE_TEST(uint32_t, 4)
DEFINE_TEST(uint64_t, 8)

int main(int argc, char **argv)
{
    unsigned helper_version;
    CHECK(argc == 1 || (argc == 2 && strcmp(argv[1], "--missing-symbol") == 0));
    drop_privileges();
    /* Only this configured Linux ARM guest exposes the kuser page. */
    helper_version = *(const volatile unsigned *)(uintptr_t)0xffff0ffc;
    CHECK(helper_version >= 5);
    printf("PHANTOWD_ATOMIC_ENV uid=1000 caps=0 nnp=1 helper_version=%u\n", helper_version);
    library = dlopen(LIBRARY, RTLD_NOW | RTLD_LOCAL);
    CHECK(library != NULL);
    if (argc == 2) (void)resolve("__atomic_phantowd_missing");
    test_1(); test_2(); test_4(); test_8();
    CHECK(dlclose(library) == 0);
    puts("PHANTOWD_ATOMIC_READY scope=arm926-qemu-only widths=4 symbols=36");
    return 0;
}
