#ifndef __BOX64CONTEXT_H_
#define __BOX64CONTEXT_H_
#include <stdint.h>
#include "pathcoll.h"
#include "dictionnary.h"
#include <link.h>
#include "debug.h"

typedef struct elfheader_s elfheader_t;
typedef struct cleanup_s cleanup_t;
typedef struct lib_s lib_t;
typedef struct bridge_s bridge_t;
typedef struct kh_symbolmap_s kh_symbolmap_t;
typedef struct kh_symbol1map_s kh_symbol1map_t;
typedef struct library_s library_t;
typedef struct linkmap_s linkmap_t;
typedef struct kh_threadstack_s kh_threadstack_t;
typedef struct guest_object_registry_s guest_object_registry_t;
typedef struct atfork_fnc_s {
    uintptr_t prepare;
    uintptr_t parent;
    uintptr_t child;
    void*     handle;
} atfork_fnc_t;
#define DYNAMAP_SHIFT 16
#define JMPTABL_SHIFT 16

typedef void* (*procaddess_t)(const char* name);
typedef void* (*vkprocaddess_t)(void* instance, const char* name);

#define MAX_SIGNAL 64

typedef struct needed_libs_s {
    int         cap;
    int         size;
    library_t   **libs;
} needed_libs_t;

void add_neededlib(needed_libs_t* needed, library_t* lib);
void free_neededlib(needed_libs_t* needed);
void add_dependedlib(needed_libs_t* depended, library_t* lib);
void free_dependedlib(needed_libs_t* depended);

typedef struct dlprivate_s {
    library_t   **libs;
    void        **handles;
    size_t      *count;
    size_t      *dlopened;
    size_t      lib_sz;
    size_t      lib_cap;
    char*       last_error;
    char*       last_error_returned;
    void *     x86dlopen;
    void *     x86dlmopen;
    void *     x86dlclose;
    void *     x86dlsym;
    void *     x86dladdr1;
    void *     x86dladdr;
    void *     x86dlinfo;
    void *     x86dlvsym;
    void *     x86dlerror;
} dlprivate_t;
struct latx_kzt_debug {
    char *name;
    int type;
    unsigned long map_start;
    unsigned long map_end;
};

/*
 * Only the public ABI prefix from <link.h> is used here. Glibc fields after
 * l_prev are private and their offsets change between loader versions.
 */
struct link_map_x64 {
    Elf64_Addr l_addr;
    char *l_name;
    Elf64_Dyn *l_ld;
    struct link_map_x64 *l_next;
    struct link_map_x64 *l_prev;
};
struct malloc_map {
    void* mallocp;
    void* freep;
    void* reallocp;
    void* h;
};
typedef struct box64context_s {
    path_collection_t   box64_path;     // PATH env. variable
    path_collection_t   box64_ld_lib;   // LD_LIBRARY_PATH env. variable

    path_collection_t   box64_emulated_libs;    // Collection of libs that should not be wrapped

    int                 x64trace;
    int                 trace_tid;

    uint32_t            sel_serial;     // will be increment each time selectors changes

    void*               box64lib;       // dlopen on box64 itself

    int                 argc;
    char**              argv;

    int                 envc;
    char**              envv;

    char*               fullpath;
    char*               box64path;      // path of current box64 executable
    char*               box86path;      // path of box86 executable (if present)
    char*               bashpath;       // path of x86_64 bash (defined with BOX64_BASH or by running bash directly)

    uint64_t            stacksz;
    size_t              stackalign;
    void*               stack;          // alocated stack

    elfheader_t         **elfs;         // elf headers and memory
    int                 elfcap;
    int                 elfsize;        // number of elf loaded
    guest_object_registry_t *guest_objects;

    struct malloc_map          **mallocmaps;         // elf filepath and memory
    int                 mallocmapcap;
    int                 mallocmapsize;        // number of elf filepath

    needed_libs_t       neededlibs;     // needed libs for main elf

    uintptr_t           ep;             // entry point

    lib_t               *maplib;        // lib and symbols handling
    lib_t               *local_maplib;  // libs and symbols openned has local (only collection of libs, no symbols)
    dic_t               *versym;        // dictionnary of versionned symbols

    kh_threadstack_t    *stacksizes;    // stack sizes attributes for thread (temporary)
    bridge_t            *system;        // other bridges
    uintptr_t           vsyscall;       // vsyscall bridge value
    uintptr_t           vsyscalls[3];   // the 3 x86 VSyscall pseudo bridges (mapped at 0xffffffffff600000+)
    dlprivate_t         *dlprivate;     // dlopen library map
    kh_symbolmap_t      *glwrappers;    // the map of wrapper for glProcs (for GLX or SDL1/2)
    kh_symbolmap_t      *glmymap;       // link to the mysymbolmap of libGL
    procaddess_t        glxprocaddress;
    kh_symbolmap_t      *alwrappers;    // the map of wrapper for alGetProcAddress
    kh_symbolmap_t      *almymap;       // link to the mysymbolmap if libOpenAL
    kh_symbol1map_t      *vkwrappers;    // the map of wrapper for VulkanProcs (TODO: check SDL2)
    kh_symbol1map_t      *vkmymap;       // link to the mysymbolmap of libGL
    vkprocaddess_t      vkprocaddress;
    #ifndef DYNAREC
    pthread_mutex_t     mutex_lock;     // dynarec build will use their own mecanism
    pthread_mutex_t     mutex_trace;
    pthread_mutex_t     mutex_tls;
    pthread_mutex_t     mutex_thread;
    pthread_mutex_t     mutex_bridge;
    #else
    #ifdef USE_CUSTOM_MUTEX
    uint32_t            mutex_dyndump;
    uint32_t            mutex_trace;
    uint32_t            mutex_tls;
    uint32_t            mutex_thread;
    uint32_t            mutex_bridge;
    #else
    pthread_mutex_t     mutex_dyndump;
    pthread_mutex_t     mutex_trace;
    pthread_mutex_t     mutex_tls;
    pthread_mutex_t     mutex_thread;
    pthread_mutex_t     mutex_bridge;
    #endif
    uintptr_t           max_db_size;    // the biggest (in x86_64 instructions bytes) built dynablock
    int                 trace_dynarec;
    pthread_mutex_t     mutex_lock;     // this is for the Test interpreter
    #ifdef __riscv
    uint32_t            mutex_16b;
    #endif
    #endif

    library_t           *libclib;       // shortcut to libc library (if loaded, so probably yes)
    library_t           *sdl1lib;       // shortcut to SDL1 library (if loaded)
    void*               sdl1allocrw;
    void*               sdl1freerw;
    library_t           *sdl1mixerlib;
    library_t           *sdl2lib;       // shortcut to SDL2 library (if loaded)
    void*               sdl2allocrw;
    void*               sdl2freerw;
    library_t           *sdl2mixerlib;
    library_t           *x11lib;
    library_t           *zlib;
    library_t           *vorbisfile;
    library_t           *vorbis;
    library_t           *asound;
    library_t           *pulse;
    library_t           *d3dadapter9;
    library_t           *libglu;
    linkmap_t           *linkmap;

    int                 deferedInit;
    elfheader_t         **deferedInitList;
    int                 deferedInitSz;
    int                 deferedInitCap;

    uintptr_t           *auxval_start;

    cleanup_t   *cleanups;          // atexit functions
    int         clean_sz;
    int         clean_cap;


    int                 forked;         //  how many forks... cleanup only when < 0

    atfork_fnc_t        *atforks;       // fnc for atfork...
    int                 atfork_sz;
    int                 atfork_cap;

    uint8_t             canary[8];

    uintptr_t           signals[MAX_SIGNAL];
    uintptr_t           restorer[MAX_SIGNAL];
    int                 onstack[MAX_SIGNAL];
    int                 is_sigaction[MAX_SIGNAL];
    int                 no_sigsegv;
    int                 no_sigill;
    void*               stack_clone;
    int                 stack_clone_used;

    int                 current_line;
#ifdef CONFIG_LATX_DEBUG
    struct latx_kzt_debug **latx_kzt_debugs;
    int                 latx_kzt_debugcap;
    int                 latx_kzt_debugsize;        // number of latx_kzt_debug
#endif
} box64context_t;

extern box64context_t *my_context; // global context

box64context_t *NewBox64Context(int argc);
void FreeBox64Context(box64context_t** context);

// return the index of the added header
int AddElfHeader(box64context_t* ctx, elfheader_t* head);
int AddMallocMap(box64context_t* ctx, struct malloc_map* map);
struct malloc_map * SearchMallocMap(box64context_t* ctx, char *elfname);
#if defined(CONFIG_LATX_KZT) && defined(CONFIG_LATX_DEBUG)
int AddKztDebugInfo(box64context_t* ctx, struct latx_kzt_debug* debuginfo);
#endif
#endif //__BOX64CONTEXT_H_
