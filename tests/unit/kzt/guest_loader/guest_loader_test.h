#ifndef WI600_GUEST_LOADER_TEST_H
#define WI600_GUEST_LOADER_TEST_H

typedef long wi600_lmid_t;
typedef int (*wi600_value_function_t)(void);

extern void *dlopen(const char *filename, int flags);
extern void *dlmopen(wi600_lmid_t lmid, const char *filename, int flags);
extern int dlclose(void *handle);
extern void *dlsym(void *handle, const char *symbol);
extern void *dlvsym(void *handle, const char *symbol, const char *version);
extern char *dlerror(void);
extern int dlinfo(void *handle, int request, void *argument);

#define WI600_RTLD_LAZY 0x00001
#define WI600_RTLD_NOW 0x00002
#define WI600_RTLD_NOLOAD 0x00004
#define WI600_RTLD_LOCAL 0x00000
#define WI600_RTLD_GLOBAL 0x00100
#define WI600_RTLD_NODELETE 0x01000
#define WI600_RTLD_DEFAULT ((void *)0)
#define WI600_LM_ID_BASE 0L
#define WI600_LM_ID_NEWLM (-1L)
#define WI600_RTLD_DI_LMID 1
#define WI600_RTLD_DI_LINKMAP 2

static inline long wi600_raw_syscall3(long number, long argument1,
                                      long argument2, long argument3)
{
    long result;

    __asm__ volatile(
        "syscall"
        : "=a"(result)
        : "a"(number), "D"(argument1), "S"(argument2), "d"(argument3)
        : "rcx", "r11", "memory");
    return result;
}

static inline __attribute__((noreturn)) void wi600_exit(int status)
{
    __asm__ volatile(
        "syscall"
        :
        : "a"(60L), "D"((long)status)
        : "rcx", "r11", "memory");
    __builtin_unreachable();
}

static inline unsigned long wi600_string_length(const char *text)
{
    unsigned long length = 0;

    while (text[length]) {
        ++length;
    }
    return length;
}

static inline void wi600_write_text(int descriptor, const char *text)
{
    (void)wi600_raw_syscall3(1, descriptor, (long)text,
                            (long)wi600_string_length(text));
}

static inline __attribute__((noreturn)) void wi600_fail(
    const char *scenario, int status, const char *detail)
{
    wi600_write_text(2, "WI600_GUEST_LOADER_FAIL ");
    wi600_write_text(2, scenario);
    wi600_write_text(2, ": ");
    wi600_write_text(2, detail);
    wi600_write_text(2, "\n");
    wi600_exit(status);
}

static inline void wi600_require(int condition, const char *scenario,
                                 int status, const char *detail)
{
    if (!condition) {
        wi600_fail(scenario, status, detail);
    }
}

static inline void wi600_clear_dlerror(void)
{
    (void)dlerror();
}

static inline wi600_value_function_t wi600_value_symbol(void *handle,
                                                        const char *name)
{
    union {
        void *object;
        wi600_value_function_t function;
    } symbol;

    symbol.object = dlsym(handle, name);
    return symbol.function;
}

static inline wi600_value_function_t wi600_versioned_value_symbol(
    void *handle, const char *name, const char *version)
{
    union {
        void *object;
        wi600_value_function_t function;
    } symbol;

    symbol.object = dlvsym(handle, name, version);
    return symbol.function;
}

static inline __attribute__((noreturn)) void wi600_pass(const char *scenario)
{
    wi600_write_text(1, "WI600_GUEST_LOADER_PASS ");
    wi600_write_text(1, scenario);
    wi600_write_text(1, "\n");
    wi600_exit(0);
}

#endif
