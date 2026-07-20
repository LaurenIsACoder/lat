/*
 * This file is derived from Box64.
 *
 * SPDX-FileCopyrightText: 2020 ptitSeb
 *
 * SPDX-License-Identifier: MIT
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "elf.h"
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <link.h>
#include <unistd.h>
#include <errno.h>

#include "elfloader.h"
#include "debug.h"
#include "elfload_dump.h"
#include "elfloader_private.h"
#include "librarian.h"
#include "bridge.h"
#include "wrapper.h"
#include "box64context.h"
#include "library.h"
#include "library_private.h"
#include "dictionnary.h"
#include "symbols.h"
#include "lsenv.h"
#include "kzt_rela_stub_detector.h"
#include "kzt_guest_registry.h"
#include "kzt_observation_adapter.h"
#include "kzt_jump_slot_production.h"
#include "kzt_lazy_diagnostics.h"
#include "kzt_plt_resolver_adapter.h"
#include "elf_plt_relocation.h"
#include "elfmap.h"

#ifdef CONFIG_LATX_KZT
#include "qemu.h"
extern int wine_option_kzt;
#endif

void* my__IO_2_1_stderr_ = NULL;
void* my__IO_2_1_stdin_  = NULL;
void* my__IO_2_1_stdout_ = NULL;
void ResetSpecialCaseMainElf(elfheader_t* h)
{
    Elf64_Sym *sym = NULL;
    for (size_t i=0; i<h->numDynSym; ++i) {
        if(h->DynSym[i].st_info == 17) {
            sym = h->DynSym+i;
            const char * symname = h->DynStr+sym->st_name;
            if(strcmp(symname, "_IO_2_1_stderr_")==0 && ((void*)sym->st_value+h->delta)) {
                memcpy((void*)sym->st_value+h->delta, stderr, sym->st_size);
                my__IO_2_1_stderr_ = (void*)sym->st_value+h->delta;
                printf_log(LOG_DEBUG, "BOX64: Set @_IO_2_1_stderr_ to %p\n", my__IO_2_1_stderr_);
            } else
            if(strcmp(symname, "_IO_2_1_stdin_")==0 && ((void*)sym->st_value+h->delta)) {
                memcpy((void*)sym->st_value+h->delta, stdin, sym->st_size);
                my__IO_2_1_stdin_ = (void*)sym->st_value+h->delta;
                printf_log(LOG_DEBUG, "BOX64: Set @_IO_2_1_stdin_ to %p\n", my__IO_2_1_stdin_);
            } else
            if(strcmp(symname, "_IO_2_1_stdout_")==0 && ((void*)sym->st_value+h->delta)) {
                memcpy((void*)sym->st_value+h->delta, stdout, sym->st_size);
                my__IO_2_1_stdout_ = (void*)sym->st_value+h->delta;
                printf_log(LOG_DEBUG, "BOX64: Set @_IO_2_1_stdout_ to %p\n", my__IO_2_1_stdout_);
            } else
            if(strcmp(symname, "_IO_stderr_")==0 && ((void*)sym->st_value+h->delta)) {
                memcpy((void*)sym->st_value+h->delta, stderr, sym->st_size);
                my__IO_2_1_stderr_ = (void*)sym->st_value+h->delta;
                printf_log(LOG_DEBUG, "BOX64: Set @_IO_stderr_ to %p\n", my__IO_2_1_stderr_);
            } else
            if(strcmp(symname, "_IO_stdin_")==0 && ((void*)sym->st_value+h->delta)) {
                memcpy((void*)sym->st_value+h->delta, stdin, sym->st_size);
                my__IO_2_1_stdin_ = (void*)sym->st_value+h->delta;
                printf_log(LOG_DEBUG, "BOX64: Set @_IO_stdin_ to %p\n", my__IO_2_1_stdin_);
            } else
            if(strcmp(symname, "_IO_stdout_")==0 && ((void*)sym->st_value+h->delta)) {
                memcpy((void*)sym->st_value+h->delta, stdout, sym->st_size);
                my__IO_2_1_stdout_ = (void*)sym->st_value+h->delta;
                printf_log(LOG_DEBUG, "BOX64: Set @_IO_stdout_ to %p\n", my__IO_2_1_stdout_);
            }
        }
    }
}
void ResetSpecialCaseElf(elfheader_t* h, const char ** names, int nnames, void **rsymbol, int *nrsymbol)
{
    Elf64_Sym *sym = NULL;
    for (size_t i=0; i<h->numDynSym; ++i) {
        sym = h->DynSym+i;
        const char * symname = h->DynStr+sym->st_name;
        for (int ii = 0; ii < nnames; ii++) {
            if(!rsymbol[ii] && strlen(symname) && !strcmp(symname, names[ii]) && ((void*)sym->st_value+h->delta)) {
                rsymbol[ii] = (void*)sym->st_value+h->delta;
                (*nrsymbol)++;
                printf_dlsym(LOG_DEBUG, "BOX64: Set @%s to %p %d\n", names[ii], rsymbol[ii], h->DynSym[i].st_info);
            }
        }
        //printf_dlsym(LOG_VERBOSE, "debug %s addr %p %d\n", symname, (void*)sym->st_value+h->delta, h->DynSym[i].st_info);
    }
}
// return the index of header (-1 if it doesn't exist)
int getElfIndex(box64context_t* ctx, elfheader_t* head) {
    for (int i=0; i<ctx->elfsize; ++i)
        if(ctx->elfs[i]==head)
            return i;
    return -1;
}

elfheader_t* Init_Elfheader(void)
{
    elfheader_t *h = box_calloc(1, sizeof(elfheader_t));
    return h;
}
elfheader_t* LoadAndCheckElfHeader(FILE* f, const char* name, int exec)
{
    elfheader_t *h = ParseElfHeader(f, name, exec);
    if(!h)
        return NULL;

    if ((h->path = realpath(name, NULL)) == NULL) {
        h->path = (char*)box_malloc(1);
        h->path[0] = '\0';
    }

    h->file = f;
    h->fileno = fileno(f);
    return h;
}

elfheader_t* ParseElfHeader_SO(int fd, const char* name, struct elf64_hdr* header);
elfheader_t* LoadAndCheck_SO(int fd, const char* name, Elf64_Ehdr* header)
{
    elfheader_t *h = ParseElfHeader_SO(fd, name, header);
    if(!h)
        return NULL;

    if ((h->path = realpath(name, NULL)) == NULL) {
        h->path = (char*)box_malloc(1);
        h->path[0] = '\0';
    }
    return h;
}

#if 1
uintptr_t loadSoaddrFromMap(char * real_path)
{
    char buf[PATH_MAX];
    FILE *f = fopen("/proc/self/maps", "r");
    uintptr_t s = 0, e = 0, offset = 0;
    if(!f)
        return 0;
    while(!feof(f)) {
        char* ret = fgets(buf, sizeof(buf), f);
        (void)ret;
        if (strstr(buf, real_path)) {
            if (sscanf(buf, "%lx-%lx %*4s %lx ", &s, &e, &offset) == 3) {
                break;
            } else {
                lsassert(0);
            }
        }
    }
    fclose(f);
    return s - offset;
}
#endif
void ElfHeadReFix (elfheader_t* head, uintptr_t delta)
{
    head->latx_hasfix = 1;
    lsassert(delta);
    head->delta = delta;
    #define GO(a) if ((uintptr_t)head->a > 0) {   \
            if ((uintptr_t)head->a > (uintptr_t)head->delta) {   \
                head->delta = 0;                           \
            }                                             \
            return;                                       \
    };
    GO(VerSym)
    GO(DynStrTab)   
    GO(VerNeed)
    GO(entrypoint)
    GO(initentry)
    GO(initarray)
    GO(finientry)
    GO(finiarray)
    GO(rela)
    GO(jmprel)
    GO(gotplt_end)
    GO(pltgot)
    GO(got)
    GO(got_end)
    GO(plt)
    GO(plt_end)
    GO(text)
    GO(ehframe)
    GO(ehframe_end)
    GO(ehframehdr)
    #undef GO
}

extern struct elfheader_s * elf_header;

void FreeElfHeader(elfheader_t** head)
{
    if(!head || !*head)
        return;
    elfheader_t *h = *head;
    box_free(h->name);
    box_free(h->path);
    box_free(h->PHEntries);
    box_free(h->SHEntries);
    box_free(h->SHStrTab);
    box_free(h->StrTab);
    box_free(h->Dynamic);
    box_free(h->DynStr);
    box_free(h->SymTab);
    box_free(h->DynSym);

    box_free(h);

    *head = NULL;
}
#include "fileutils.h"
#define GO(P, N) P,
#define GOALIAS(P, N) P,
const char * wrappedlibs_name[] = {
#include "library_list.h"
};
#undef GO
#undef GOALIAS
static int qsort_strcmp(const void *a, const void *b)
{
    return strcmp(*(char *const *)a, *(char *const *)b);
}

static char* GenPathList(char * rpath, const char* origin)
{
    char *rpathref = rpath;
    while (strstr(rpath, "$ORIGIN")) {
        char* p = strrchr(origin, '/');
        if (p) *p = '\0';    // remove file name to have only full path, without last '/'
        char* tmp = (char*)box_calloc(1, strlen(rpath)-strlen("$ORIGIN")+strlen(origin)+1);
        p = strstr(rpath, "$ORIGIN");
        memcpy(tmp, rpath, p-rpath);
        strcat(tmp, origin);
        strcat(tmp, p+strlen("$ORIGIN"));
        if (rpath!=rpathref)
            box_free(rpath);
        rpath = tmp;
    }
    while (strstr(rpath, "${ORIGIN}")) {
        char* p = strrchr(origin, '/');
        if (p) *p = '\0';    // remove file name to have only full path, without last '/'
        char* tmp = (char*)box_calloc(1, strlen(rpath)-strlen("${ORIGIN}")+strlen(origin)+1);
        p = strstr(rpath, "${ORIGIN}");
        memcpy(tmp, rpath, p-rpath);
        strcat(tmp, origin);
        strcat(tmp, p+strlen("${ORIGIN}"));
        if (rpath!=rpathref)
            box_free(rpath);
        rpath = tmp;
    }
    while (strstr(rpath, "${PLATFORM}")) {
        char* platform = box_strdup("x86_64");
        char* p = strrchr(platform, '/');
        if (p) *p = '\0';    // remove file name to have only full path, without last '/'
        char* tmp = (char*)box_calloc(1, strlen(rpath)-strlen("${PLATFORM}")+strlen(platform)+1);
        p = strstr(rpath, "${PLATFORM}");
        memcpy(tmp, rpath, p-rpath);
        strcat(tmp, platform);
        strcat(tmp, p+strlen("${PLATFORM}"));
        if (rpath!=rpathref)
            box_free(rpath);
        rpath = tmp;
        box_free(platform);
    }
    if (strchr(rpath, '$')) {
        printf_log(LOG_INFO, "BOX64: Warning, RPATH with $ variable not supported yet (%s)\n", rpath);
    }
    printf_log(LOG_INFO, "Generated: %s\n", rpath);
    return rpath;
}

static char* find_so_from_path(char* filename, path_collection_t* lib_path,
                               int *so_index)
{
    char realpath[PATH_MAX];
    int j = 0;
    for (; (*so_index) < lib_path->size; ++(*so_index)) {
        j = (*so_index);
        snprintf(realpath, PATH_MAX, "%s/%s", lib_path->paths[j], filename);
        if(FileExist((const char*)realpath, IS_FILE)) {
            char *retpath = box_malloc(strlen(realpath) + 1);
            strcpy(retpath, realpath);
            return retpath;
        }
    }
    return NULL;
}
//elf file only has DT_RPATH or DT_RPATH.
static char* find_elf_rpath(char* rfilename, bool* elf_err)
{
    int fd = open(rfilename, O_RDONLY, 0);
    FILE *f = fdopen(fd, "rb");
    char *rpath;
    struct stat statbuf;

    if(!f) {
        printf_log(LOG_INFO, "%s Error: Cannot open \"%s\"\n", __func__, rfilename);
        return NULL;
    }
    if (stat(rfilename, &statbuf)) {
        printf_log(LOG_INFO, "%s: Error stat %s failed\n", __func__, rfilename);
        return NULL;
    }
    lsassert(statbuf.st_size);
    elfheader_t* h = LoadAndCheckElfHeader(f, rfilename, 0);
    if (h == NULL) {
        *elf_err = true;
        return NULL;
    }
    for (size_t i=0; i<h->numDynamic; ++i) {
        switch(h->Dynamic[i].d_tag) {
            case DT_RPATH:
            case DT_RUNPATH:
                lsassert(h->DynStr);
                rpath = h->DynStr + h->Dynamic[i].d_un.d_val;
                printf_log(LOG_INFO, "RPATH : %s\n", rpath);
                lsassert(h->path);
                char * tmporg = strdup(h->path);
                char * retpath = GenPathList(rpath, tmporg);
                if (retpath == rpath) {
                    retpath = strdup(retpath);
                }
                free(tmporg);
                FreeElfHeader(&h);
                fclose(f);
                return retpath;
        }
    }
    FreeElfHeader(&h);
    fclose(f);
    return NULL;
}
static void for_needed_check(elfheader_t* h, int needlibcnt, path_collection_t *lib_path)
{
    //for needed
    const char* rpaths[needlibcnt];
    const char* rpaths_filepath[needlibcnt];
    int j=0;
    for (int i=0; i<h->numDynamic; ++i) {
        if(h->Dynamic[i].d_tag==DT_NEEDED) {
            if (strstr(h->DynStrTab+h->delta+h->Dynamic[i].d_un.d_val, "ld-linux-x86-64.so.2")) {
                continue;
            }
            // LD_LIBRARY_PATH may have multiple fitable paths
            int so_index =0;
            while (so_index < lib_path->size) {
                char* tmp = find_so_from_path(
                    h->DynStrTab + h->delta + h->Dynamic[i].d_un.d_val,
                    lib_path, &so_index);

                if (tmp) {
                    bool elf_err = false;
                    const char* result_tmp = find_elf_rpath(tmp, &elf_err);
                    if (!elf_err) {
                        rpaths_filepath[j] = tmp;
                        rpaths[j] = result_tmp;
                        j++;
                        break;
                    }
                }
                so_index++;
            }
        }
    }
    path_collection_t   tmp_path = {0,0,0};
    for (int i = 0;i < j; i++) {
        if(rpaths[i] && strlen(rpaths[i])) {
            rpaths[i] = GenPathList((char *)rpaths[i], rpaths_filepath[i]);
            AppendListExistAndNotSys(&tmp_path, rpaths[i], 1);
        }
    }
    for (int i = 0;i < j; i++) {
        if (rpaths[i]) {
            box_free((char*)rpaths[i]);
        }
        box_free((char*)rpaths_filepath[i]);
    }
    qsort(tmp_path.paths, tmp_path.size, sizeof(char *), qsort_strcmp);
    if (tmp_path.size >= 2) {
        char * hadinsert = NULL;
        for (int i = 0; i< tmp_path.size;i++) {
            if (strlen(tmp_path.paths[i]) && (!hadinsert||strcmp(tmp_path.paths[i], hadinsert))) {
                int not_found = 0;
                for(int ii = 0; ii < lib_path->size; ii++) {
                    if (!strcmp(lib_path->paths[ii], tmp_path.paths[i])) {
                        not_found = 1;
                        break;
                    }
                }
                if (!not_found) {
                    AddPath(tmp_path.paths[i], lib_path, 1);
                    //fprintf(stderr, "latx debug add %s\n", tmp_path.paths[i]);
                }
                hadinsert = tmp_path.paths[i];
            }
        }
    }
    //free tmp_path
    FreeCollection(&tmp_path);
}

static int isChromeApp(elfheader_t* h, int con_score)
{
    Elf64_Sym *sym = NULL;
    char symnamebuf[1024];
    int find_key_score = 0;
#define KEY_SPLIT " "
#define KEY_LEVEL(level) KEY_SPLIT#level

    const char * chromekeys =
                                                           KEY_SPLIT
        "_ZdaPv"                                           KEY_LEVEL(1)KEY_SPLIT
        "ChromeMain"                                       KEY_LEVEL(10)KEY_SPLIT
        "_ZdaPvm"                                          KEY_LEVEL(1)KEY_SPLIT
        "_ZdaPvmSt11align_val_t"                           KEY_LEVEL(1)KEY_SPLIT
        "_ZdaPvRKSt9nothrow_t"                             KEY_LEVEL(1)KEY_SPLIT
        "_ZdaPvSt11align_val_t"                            KEY_LEVEL(1)KEY_SPLIT
        "_ZdaPvSt11align_val_tRKSt"                        KEY_LEVEL(1)KEY_SPLIT
        "_ZdlPv"                                           KEY_LEVEL(1)KEY_SPLIT
        "_ZdlPvm"                                          KEY_LEVEL(1)KEY_SPLIT
        "_ZdlPvmSt11align_val_t"                           KEY_LEVEL(1)KEY_SPLIT
        "_ZdlPvRKSt9nothrow_t"                             KEY_LEVEL(1)KEY_SPLIT
        "_ZdlPvSt11align_val_t"                            KEY_LEVEL(1)KEY_SPLIT
        "_ZdlPvSt11align_val_tRKSt"                        KEY_LEVEL(1)KEY_SPLIT
        "_Znam"                                            KEY_LEVEL(1)KEY_SPLIT
        "_ZnamRKSt9nothrow_t"                              KEY_LEVEL(1)KEY_SPLIT
        "_ZnamSt11align_val_t"                             KEY_LEVEL(1)KEY_SPLIT
        "_ZnamSt11align_val_tRKSt9"                        KEY_LEVEL(1)KEY_SPLIT
        "_Znwm"                                            KEY_LEVEL(1)KEY_SPLIT
        "_ZnwmRKSt9nothrow_t"                              KEY_LEVEL(1)KEY_SPLIT
        "_ZnwmSt11align_val_t"                             KEY_LEVEL(1)KEY_SPLIT
        "_ZnwmSt11align_val_tRKSt9"                        KEY_LEVEL(1)KEY_SPLIT;
    for (size_t i=0; i<h->numDynSym; ++i) {
        sym = h->DynSym+i;
        if (h->DynSym[i].st_shndx != SHN_UNDEF && sym->st_value) {
            int score = 0;
            char *find_offset;
            const char * symname = h->DynStr+sym->st_name;
            snprintf(symnamebuf, 1023, KEY_SPLIT"%s"KEY_SPLIT, symname);
            find_offset = strstr(chromekeys, symnamebuf);
            if (find_offset) {
                snprintf(symnamebuf, 1023, KEY_SPLIT"%s"KEY_SPLIT"%%d"KEY_SPLIT, symname);
                if (sscanf(find_offset, symnamebuf, &score) == 1) {
                    find_key_score += score;
                    //if find_key_score >= con_score. exe is chrome app
                    if (find_key_score >= con_score) {
                        return 1;
                    }
                }
            }
        }
    }
#undef KEY_SPLIT
    return 0;
}

int CheckEnableKZT(elfheader_t* h, char** target_argv, int target_argc)
{
    path_collection_t   lib_path = {0,0,0};
    char *rpath;

    int needlibcnt = 0;
    /* get paths from RPATH/RUNPATH/LD_LIBRARY_PATH,
     * exclude system paths and non-exist paths */
    for (size_t i=0; i<h->numDynamic; ++i) {
        switch(h->Dynamic[i].d_tag) {
            case DT_RPATH:
            case DT_RUNPATH:
                rpath =  h->DynStrTab+h->Dynamic[i].d_un.d_val + h->delta;
                    printf_log(LOG_INFO, "RPATH : %s\n", rpath);
                rpath = GenPathList(rpath, h->path);
                AppendListExistAndNotSys(&lib_path, rpath, 1);
                break;
            case DT_NEEDED:
                if (strstr(h->DynStrTab+h->delta+h->Dynamic[i].d_un.d_val, "libgtk-3.so")||//skip gtk
                    strstr(h->DynStrTab+h->delta+h->Dynamic[i].d_un.d_val, "libXt.so")) {//skip mainexec needed libXt.so
                    printf_log(LOG_INFO, "latx find libgtk or libXt, skip kzt\n");
                    return 0;
                }
                ++needlibcnt;
                break;
        }
    }
    if (getenv("LD_LIBRARY_PATH"))
        AppendListExistAndNotSys(&lib_path, getenv("LD_LIBRARY_PATH"), 1);   // in case some of the path are for x86 world

    for (int i=0; i<lib_path.size; ++i)
        printf_log(LOG_INFO, "%s\n", lib_path.paths[i]);
    for_needed_check(h, needlibcnt, &lib_path);
    /* check KZT libs in paths */
    int nb = sizeof(wrappedlibs_name) / sizeof(char*);
    for (int i=0; i<nb; ++i) {
        char *p = box_strdup(wrappedlibs_name[i]);
        char *p2 = strchr(p, '.');
        if (++p2) {
            *p2 = '\0';
        }
        for (int j=0; j<lib_path.size; ++j) {
            DIR *dir = opendir(lib_path.paths[j]);
            if (dir == NULL) {
                printf_log(LOG_INFO, "dir %s not exist\n", lib_path.paths[j]);
                continue;
            }

            struct dirent *entry;
            while ((entry = readdir(dir)) != NULL) {
                if (entry->d_type == DT_REG) {  // Check if it's a regular file
                    if (!strncmp(entry->d_name, p, strlen(p))) {
                        printf_log(LOG_INFO, "File starting with '%s' found: %s at %s\n", p, entry->d_name, lib_path.paths[j]);
                        closedir(dir);
                        FreeCollection(&lib_path);
                        return 0;
                    }
                }
            }
            closedir(dir);
        }
    }
    FreeCollection(&lib_path);
    //disable kzt chrome app
    for(int i = 0; i < target_argc; i++) {
        if (!strcmp(target_argv[i], "--no-sandbox")) {
            return !isChromeApp(h, 5);
        }
    }
    return !isChromeApp(h, 10);
}

const char* ElfName(elfheader_t* head)
{
    if(!head)
        return "(noelf)";
    return head->name;
}
const char* ElfPath(elfheader_t* head)
{
    if(!head)
        return NULL;
    return head->path;
}

void ElfAttachLib(elfheader_t* head, library_t* lib)
{
    if(!head)
        return;
    head->lib = lib;
}

int GetVersionIndice(elfheader_t* h, const char* vername)
{
    if(!vername)
        return 0;
    if(h->VerDef) {
        Elf64_Verdef *def = (Elf64_Verdef*)((uintptr_t)h->VerDef + h->delta);
        while(def) {
            Elf64_Verdaux *aux = (Elf64_Verdaux*)((uintptr_t)def + def->vd_aux);
            if(!strcmp(h->DynStr+aux->vda_name, vername))
                return def->vd_ndx;
            def = def->vd_next?((Elf64_Verdef*)((uintptr_t)def + def->vd_next)):NULL;
        }
    }
    return 0;
}

int GetNeededVersionCnt(elfheader_t* h, const char* libname)
{
    if(!libname)
        return 0;
    if(h->VerNeed) {
        Elf64_Verneed *ver = (Elf64_Verneed*)((uintptr_t)h->VerNeed + h->delta);
        while(ver) {
            char *filename = h->DynStr + ver->vn_file;
            if(!strcmp(filename, libname))
                return ver->vn_cnt;
            ver = ver->vn_next?((Elf64_Verneed*)((uintptr_t)ver + ver->vn_next)):NULL;
        }
    }
    return 0;
}

const char* GetNeededVersionString(elfheader_t* h, const char* libname, int idx)
{
    if(!libname)
        return 0;
    if(h->VerNeed) {
        Elf64_Verneed *ver = (Elf64_Verneed*)((uintptr_t)h->VerNeed + h->delta);
        while(ver) {
            char *filename = h->DynStr + ver->vn_file;
            Elf64_Vernaux *aux = (Elf64_Vernaux*)((uintptr_t)ver + ver->vn_aux);
            if(!strcmp(filename, libname)) {
                for(int j=0; j<ver->vn_cnt; ++j) {
                    if(j==idx)
                        return h->DynStr+aux->vna_name;
                    aux = (Elf64_Vernaux*)((uintptr_t)aux + aux->vna_next);
                }
                return NULL;    // idx out of bound, return NULL...
           }
            ver = ver->vn_next?((Elf64_Verneed*)((uintptr_t)ver + ver->vn_next)):NULL;
        }
    }
    return NULL;
}
/*
static int FindR64COPYRel(elfheader_t* h, const char* name, uintptr_t *offs, uint64_t** p, int version, const char* vername)
{
    if(!h)
        return 0;
    Elf64_Rela * rela = (Elf64_Rela *)(h->rela + h->delta);
    if(!h->rela)
        return 0;
    int cnt = h->relasz / h->relaent;
    for (int i=0; i<cnt; ++i) {
        int t = ELF64_R_TYPE(rela[i].r_info);
        Elf64_Sym *sym = &h->DynSym[ELF64_R_SYM(rela[i].r_info)];
        const char* symname = SymName(h, sym);
        if(t==R_X86_64_COPY && symname && !strcmp(symname, name)) {
            int version2 = h->VerSym?((Elf64_Half*)((uintptr_t)h->VerSym+h->delta))[ELF64_R_SYM(rela[i].r_info)]:-1;
            if(version2!=-1) version2 &= 0x7fff;
            if(version && !version2) version2=-1;   // match a versionned symbol against a global "local" symbol
            const char* vername2 = GetSymbolVersion(h, version2);
            if(SameVersionnedSymbol(name, version, vername, symname, version2, vername2)) {
                *offs = sym->st_value + h->delta;
                *p = (uint64_t*)(rela[i].r_offset + h->delta + rela[i].r_addend);
                return 1;
            }
        }
    }
    return 0;
}
*/

int RelocateElfRELA(lib_t *maplib, lib_t *local_maplib, int bindnow, elfheader_t* head, int cnt, Elf64_Rela *rela, int* need_resolv)
{
//    int ret_ok = 0;
    for (int i=0; i<cnt; ++i) {
        int t = ELF64_R_TYPE(rela[i].r_info);
        //we only process the type of R_X86_64_GLOB_DAT and R_X86_64_JUMP_SLO
	if(!(t == R_X86_64_GLOB_DAT || t == R_X86_64_JUMP_SLOT))
	    continue;

	Elf64_Sym *sym = &head->DynSym[ELF64_R_SYM(rela[i].r_info)];
        int bind = ELF64_ST_BIND(sym->st_info);
        const char* symname = SymName(head, sym);
        uint64_t *p = (uint64_t*)(rela[i].r_offset + head->delta);
        uintptr_t offs = 0;
        uintptr_t end = 0;
        library_t *resolved_provider = NULL;
        int version = head->VerSym?((Elf64_Half*)((uintptr_t)head->VerSym+head->delta))[ELF64_R_SYM(rela[i].r_info)]:-1;
        if(version!=-1) version &=0x7fff;
        const char* vername = GetSymbolVersion(head, version);
        if(bind==STB_LOCAL) {
            offs = sym->st_value + head->delta;
            end = offs + sym->st_size;
        } else {
            // this is probably very very wrong. A proprer way to get reloc need to be writen, but this hack seems ok for now
            // at least it work for half-life, unreal, ut99, zsnes, Undertale, ColinMcRae Remake, FTL, ShovelKnight...
            /*if(bind==STB_GLOBAL && (ndx==10 || ndx==19) && t!=R_X86_64_GLOB_DAT) {
                offs = sym->st_value + head->delta;
                end = offs + sym->st_size;
            }*/
            // so weak symbol are the one left
            if(!offs && !end) {
                GetGlobalSymbolStartEndWithProvider(
                    maplib, symname, &offs, &end, head, version, vername,
                    &resolved_provider);
                if(!offs && !end && local_maplib) {
                    GetGlobalSymbolStartEndWithProvider(
                        local_maplib, symname, &offs, &end, head, version,
                        vername, &resolved_provider);
                }
            }
        }

        //uintptr_t globoffs=0, globend=0;
        uintptr_t tmp = 0;
        switch(t) {
             case R_X86_64_GLOB_DAT:
                    // Look for same symbol already loaded but not in self (so no need for local_maplib here)
                   // if (GetGlobalNoWeakSymbolStartEnd(local_maplib?local_maplib:maplib, symname, &globoffs, &globend, version, vername)) {
                   //     offs = globoffs;
                   //     end = globend;
                   // }
                    if (offs) {
                        printf_log(LOG_INFO, "Apply %s R_X86_64_GLOB_DAT @%p (%p -> %p) on sym=%s (ver=%d/%s)\n", (bind==STB_LOCAL)?"Local":"Global", p, (void*)(p?(*p):0), (void*)offs, symname, version, vername?vername:"(none)");
                        *p = offs/* + rela[i].r_addend*/;   // not addend it seems
                    }
                break;
            case R_X86_64_JUMP_SLOT: {
                // apply immediatly for gobject closure marshal or for LOCAL binding. Also, apply immediatly if it doesn't jump in the got
                uintptr_t slot_observation = (uintptr_t)(*p);
                uintptr_t expected_guest_target = slot_observation;
                uintptr_t legacy_target = offs + rela[i].r_addend;
                int slot_is_unresolved_stub =
                    kzt_rela_slot_current_is_unresolved_stub(
                        slot_observation,
                        KZT_RELA_STUB_COORDINATE_RUNTIME_REBASED,
                        head->delta, head->plt, head->plt_end,
                        head->gotplt, head->gotplt_end);
                tmp = slot_observation;
                if (bind==STB_LOCAL 
                  || !tmp
                  || !((tmp>=head->plt && tmp<head->plt_end) || (tmp>=head->gotplt && tmp<head->gotplt_end))
                  || !need_resolv
                  || bindnow
                ) {
                    if (offs){
                        if(p) {
#ifdef CONFIG_LATX_KZT
                            if (option_kzt || wine_option_kzt) {
                                kzt_jump_slot_route_result_t route_result;

                                if (kzt_production_jump_slot_route(
                                        my_context, resolved_provider,
                                        legacy_target, head,
                                        need_resolv != NULL, i,
                                        &rela[i], p,
                                    slot_observation,
                                        slot_is_unresolved_stub,
                                        ELF64_R_SYM(rela[i].r_info),
                                        symname, vername,
                                        1, expected_guest_target,
                                        legacy_target,
                                        &route_result) == 0 &&
                                    route_result.status ==
                                        KZT_JUMP_SLOT_ROUTE_NATIVE_APPLIED) {
                                    break;
                                }
                                if (route_result.status ==
                                        KZT_JUMP_SLOT_ROUTE_GUEST_PRESERVED ||
                                    route_result.status ==
                                        KZT_JUMP_SLOT_ROUTE_CAS_MISMATCH) {
                                    break;
                                }
                                printf_kzt_registry_diagnostics(
                                    "KZT eager route fallback slot=%p "
                                    "observed=%p legacy=%p selected=%p "
                                    "status=%d symbol=%s\n",
                                    p, (void *)slot_observation, (void*)legacy_target,
                                    (void *)route_result.selected_target,
                                    route_result.status,
                                    symname ? symname : "(none)");
                            }
#endif
                            printf_log(LOG_INFO, "RelocateElfRELA : Apply %s R_X86_64_JUMP_SLOT @%p with sym=%s (%p -> %p)\n", (bind==STB_LOCAL)?"Local":"Global", p, symname, *(void**)p, (void*)(offs+rela[i].r_addend));
                            *p =(uint64_t) legacy_target;
                        } else {
                            printf_log(LOG_INFO, "Warning, Symbol %s found, but Jump Slot Offset is NULL \n", symname);
                        }
                    }
                } else {
                    printf_log(LOG_INFO, "Preparing (if needed) %s R_X86_64_JUMP_SLOT @%p (0x%lx->0x%0lx) with sym=%s to be apply later (addend=%ld)\n", 
                        (bind==STB_LOCAL)?"Local":"Global", p, *p, *p+head->delta, symname, rela[i].r_addend);
                    *p += head->delta;
                    *need_resolv = 1;
                }
                break;
            }
            /*
            case R_X86_64_NONE:
                break;
            case R_X86_64_PC32:
                break;
            case R_X86_64_RELATIVE:
                break;
            case R_X86_64_IRELATIVE:
                break;
            case R_X86_64_COPY:
                break;
            case R_X86_64_64:
                break;
            */
            default:
                printf_log(LOG_INFO, "RELA: Warning, don't know of to handle rela #%d %s on %s\n", i, DumpRelType(ELF64_R_TYPE(rela[i].r_info)), symname);
        }
    }
    return 0;
}

typedef struct elf_plt_rela_context {
    lib_t *maplib;
    lib_t *local_maplib;
    int bindnow;
    elfheader_t *head;
    int count;
    Elf64_Rela *rela;
} elf_plt_rela_context_t;

static int RelocateElfPltRELA(void *opaque, int *need_resolver)
{
    elf_plt_rela_context_t *rela = opaque;
    return RelocateElfRELA(rela->maplib, rela->local_maplib, rela->bindnow,
                           rela->head, rela->count, rela->rela,
                           need_resolver);
}

#ifdef CONFIG_LATX_KZT
static void KztLazyBindingCompleteResolver(void);

static int kzt_elfloader_read_guest_memory(uintptr_t guest_addr, void *dst,
                                           size_t size, void *opaque)
{
    void *host_ptr;

    (void)opaque;
    if ((!dst && size) || (!guest_addr && size)) {
        return -1;
    }
    if (!size) {
        return 0;
    }
    host_ptr = lock_user(VERIFY_READ, (abi_ulong)guest_addr, size, true);
    if (!host_ptr) {
        return -1;
    }
    memcpy(dst, host_ptr, size);
    unlock_user(host_ptr, (abi_ulong)guest_addr, 0);
    return 0;
}

static int kzt_elfloader_head_identity(
    const elfheader_t *head,
    kzt_guest_link_map_identity_t *identity)
{
    size_t i;

    if (!head || !identity || !head->PHEntries) {
        return -1;
    }
    memset(identity, 0, sizeof(*identity));
    for (i = 0; i < head->numPHEntries; ++i) {
        const Elf64_Phdr *entry = &head->PHEntries[i];

        if (entry->p_type != PT_DYNAMIC) {
            continue;
        }
        if (head->delta < 0 ||
            entry->p_vaddr > UINTPTR_MAX - (uintptr_t)head->delta) {
            return -1;
        }
        identity->load_bias = (uintptr_t)head->delta;
        identity->dynamic_addr = entry->p_vaddr + identity->load_bias;
        return identity->dynamic_addr ? 0 : -1;
    }
    return -1;
}

static void kzt_observe_plt_source(elfheader_t *head,
                                   uintptr_t guest_link_map,
                                   const kzt_guest_link_map_identity_t *object_identity)
{
    const kzt_guest_link_map_reader_ops_t reader_ops = {
        .read_memory = kzt_elfloader_read_guest_memory,
    };
    kzt_observation_adapter_request_t request;
    kzt_observation_adapter_result_t result;
    uintptr_t map_start = 0;
    uintptr_t map_end = 0;
    uintptr_t confirmed_main_head = 0;
    uintptr_t namespace_head = 0;
    uintptr_t predecessor = 0;
    kzt_guest_registry_t *registry;
    kzt_guest_link_map_identity_t main_identity = { 0 };
    int main_namespace;
    int range_available;

    if (!head || !guest_link_map || !(option_kzt || wine_option_kzt)) {
        return;
    }
    registry = KztGuestRegistryForContext(my_context);
    (void)kzt_guest_registry_context_get_main_namespace_head(
        &my_context->kzt_guest_registry_context, &confirmed_main_head);
    if (confirmed_main_head && object_identity &&
        kzt_guest_registry_context_has_main_namespace_evidence(
            &my_context->kzt_guest_registry_context, registry,
            guest_link_map, object_identity->load_bias,
            object_identity->dynamic_addr)) {
        main_namespace = 1;
    } else {
        if (confirmed_main_head &&
            kzt_guest_link_map_read_predecessor(
                guest_link_map, &reader_ops, &predecessor) == 0 &&
            predecessor == confirmed_main_head) {
            main_namespace = 1;
        } else if (confirmed_main_head ||
            kzt_elfloader_head_identity(elf_header, &main_identity) == 0) {
            main_namespace = kzt_guest_link_map_classify_namespace(
                guest_link_map, &main_identity, confirmed_main_head, &reader_ops,
                &namespace_head);
        } else {
            main_namespace = -1;
        }
        if (main_namespace == 1 && !confirmed_main_head &&
            kzt_guest_registry_context_confirm_main_namespace_head(
                &my_context->kzt_guest_registry_context,
                &my_context->mutex_lock, namespace_head) != 0) {
            main_namespace = -1;
        }
    }
    range_available = GetElfLoadRange(
        head->PHEntries, head->numPHEntries, head->delta, TARGET_PAGE_SIZE,
        &map_start, &map_end) == 0;
    memset(&request, 0, sizeof(request));
    request.enabled = 1;
    request.link_map_addr = guest_link_map;
    request.registry = registry;
    request.library_bindings =
        KztGuestLibraryBindingsForContext(my_context);
    request.reader_ops = &reader_ops;
    request.namespace_id_present = main_namespace == 1;
    request.namespace_id = 0;
    request.map_range_present = range_available;
    request.map_start = map_start;
    request.map_end = map_end;
    result = KZT_OBSERVATION_ADAPTER_DISABLED;
    (void)kzt_observe_guest_object_from_callback(&request, &result);
    printf_kzt_registry_diagnostics(
        "KZT PLT source observation result=%d link_map=0x%lx "
        "main_namespace=%d map_start=0x%lx map_end=0x%lx\n",
        result, (unsigned long)guest_link_map, main_namespace,
        (unsigned long)map_start, (unsigned long)map_end);
}
#endif

int RelocateElfPlt(lib_t *maplib, lib_t *local_maplib, int bindnow, elfheader_t* head)
{
    int need_resolver = 0;
    uintptr_t resolver_got = head->pltgot ? head->pltgot : head->got;
    uintptr_t resolver_got_runtime = resolver_got ?
        resolver_got + head->delta : 0;
    uintptr_t guest_link_map = 0;
    uintptr_t guest_resolver = 0;
#ifdef CONFIG_LATX_KZT
    uintptr_t kzt_evidence_got = head->pltgot;
    uintptr_t kzt_evidence_got_runtime = kzt_evidence_got ?
        kzt_evidence_got + head->delta : 0;
    kzt_guest_link_map_identity_t expected_identity = { 0 };
    kzt_guest_link_map_identity_t observed_identity = { 0 };
    int resolver_snapshot_available = 0;

    if (kzt_evidence_got_runtime && (option_kzt || wine_option_kzt) &&
        kzt_elfloader_head_identity(head, &expected_identity) == 0 &&
        kzt_elfloader_read_guest_memory(
            kzt_evidence_got_runtime + 8, &guest_link_map,
            sizeof(guest_link_map), NULL) == 0 &&
        kzt_elfloader_read_guest_memory(
            kzt_evidence_got_runtime + 16, &guest_resolver,
            sizeof(guest_resolver), NULL) == 0 && guest_resolver &&
        kzt_guest_link_map_read_identity(
            guest_link_map,
            &(kzt_guest_link_map_reader_ops_t) {
                .read_memory = kzt_elfloader_read_guest_memory,
            },
            &observed_identity) == 0 &&
        kzt_guest_link_map_identity_matches(
            &observed_identity, expected_identity.load_bias,
            expected_identity.dynamic_addr)) {
        resolver_snapshot_available = 1;
        kzt_observe_plt_source(head, guest_link_map, &observed_identity);
        head->self_link_map = guest_link_map;
    }
#endif
    head->had_RelocateElfPlt = 1;
    if(head->pltrel) {
        int cnt = head->pltsz / head->pltent;
        if(head->pltrel==DT_REL) {
            //DumpRelTable(head, cnt, (Elf64_Rel *)(head->jmprel + head->delta), "PLT");
            //printf_log(LOG_INFO, "Applying %d PLT Relocation(s) for %s\n", cnt, head->name);
            //if(RelocateElfREL(maplib, local_maplib, bindnow, head, cnt, (Elf64_Rel *)(head->jmprel + head->delta)))
            //    return -1;
            return 0;
        } else if(head->pltrel==DT_RELA) {
            elf_plt_rela_context_t rela = {
                .maplib = maplib,
                .local_maplib = local_maplib,
                .bindnow = bindnow,
                .head = head,
                .count = cnt,
                .rela = (Elf64_Rela *)(head->jmprel + head->delta),
            };
            DumpRelATable(head, cnt, (Elf64_Rela *)(head->jmprel + head->delta), "PLT");
            printf_log(LOG_INFO, "Applying %d PLT Relocation(s) with Addend for %s\n", cnt, head->name);
            if(elf_plt_relocation_apply(RelocateElfPltRELA, &rela,
                                        &need_resolver)) {
                printf_log(LOG_INFO, "RelocateElfRELA run ERROR!");
                return -1;
            }
        }
        if(need_resolver) {
            if(pltResolver==~0LL) {
                pltResolver = AddBridge(my_context->system, vFE, PltResolver, 0, "PltResolver");
            }
#ifdef CONFIG_LATX_KZT
            if ((option_kzt || wine_option_kzt) &&
                !my_context->kzt_lazy_completion_bridge) {
                my_context->kzt_lazy_completion_bridge = AddBridge(
                    my_context->system, vFE,
                    KztLazyBindingCompleteResolver, 0,
                    "KztLazyBindingCompleteResolver");
            }
#endif
            if(resolver_got_runtime) {
#ifdef CONFIG_LATX_KZT
                if (!resolver_snapshot_available) {
#endif
                    guest_link_map =
                        *(uintptr_t *)(resolver_got_runtime + 8);
                    guest_resolver =
                        *(uintptr_t *)(resolver_got_runtime + 16);
#ifdef CONFIG_LATX_KZT
                }
#endif
#ifdef CONFIG_LATX_KZT
                if (option_kzt || wine_option_kzt) {
                    kzt_guest_object_snapshot_t *snapshot = NULL;
                    kzt_guest_lazy_resolver_t resolver = {
                        .link_map_slot = resolver_got_runtime + 8,
                        .resolver_slot = resolver_got_runtime + 16,
                        .guest_link_map = guest_link_map,
                        .guest_resolver = guest_resolver,
                    };
                    if (kzt_guest_registry_find_by_link_map(
                            KztGuestRegistryForContext(my_context),
                            guest_link_map, &snapshot) == 0 && snapshot &&
                        snapshot->namespace_id.status == KZT_GUEST_FIELD_OK &&
                        snapshot->namespace_id.value == 0) {
                        (void)kzt_guest_registry_publish_lazy_resolver(
                            KztGuestRegistryForContext(my_context),
                            guest_link_map, snapshot->generation, 0,
                            &resolver);
                    }
                    kzt_guest_object_snapshot_free(snapshot);
                }
#endif
                if(dl_runtime_resolver ==~0LL){
                    dl_runtime_resolver =  *(uintptr_t*)(head->got+head->delta+16);
                }
                *(uintptr_t*)(resolver_got_runtime+16) = pltResolver;
#ifdef CONFIG_LATX_KZT
                if (!(option_kzt || wine_option_kzt) ||
                    resolver_snapshot_available) {
                    head->self_link_map = guest_link_map;
                }
#else
                head->self_link_map = guest_link_map;
#endif
                *(uintptr_t*)(resolver_got_runtime+8) = (uintptr_t)head;
                printf_log(LOG_INFO, "PLT Resolver injected in got at %p\n",
                           (void*)(resolver_got_runtime+16));
            }
        }
    }
   
    return 0;
}

#if 0
#include <link.h>
#ifdef DL_RO_DYN_SECTION
# define D_PTR(map, i) ((map)->i->d_un.d_ptr + (map)->l_addr)
#else
# define D_PTR(map, i) (map)->i->d_un.d_ptr
#endif

#define	DT_NUM		35		/* Number used */
#define DT_THISPROCNUM	0

#define	DT_VERNEEDNUM	0x6fffffff	/* Number of needed versions */
#define DT_VERSIONTAGIDX(tag)	(DT_VERNEEDNUM - (tag))	/* Reverse order! */
#define VERSYMIDX(sym)	(DT_NUM + DT_THISPROCNUM + DT_VERSIONTAGIDX (sym))

int GetElfHeadFromLinkmap (struct link_map *map, elfheader_t* h)
{
    h->jmprel = D_PTR(map,l_info[DT_JMPREL])
    h->pltrel = map.l_info[DT_PLTREL]->d_un.d_val
    h->pltsz  = map.l_info[DT_PLTRELSZ]->d_un.d_val
    h->rel = map.l_info[DT_REL].d_tag
    h->rela = map.l_info[DT_RELA].d_tag
    h->DynSym = D_PTR(map,l_info[DT_SYMTAB])
    h->DynStr = D_PTR(map,l_info[DT_STRTAB])
    h->VerNeed = D_PTR (map, l_info[VERSYMIDX (DT_VERNEED)])
    h->VerDef = D_PTR (map, l_info[VERSYMIDX (DT_VERDEF)])
    h->VerSym = D_PTR (map, l_info[VERSYMIDX (DT_VERSYM)])
    return 0;
}
#endif
int RelocateElf(lib_t *maplib, lib_t *local_maplib, int bindnow, elfheader_t* head)
{
    if(head->rel) {
//        int cnt = head->relsz / head->relent;
//        DumpRelTable(head, cnt, (Elf64_Rel *)(head->rel + head->delta), "Rel");
//        printf_dump(LOG_DEBUG, "Applying %d Relocation(s) for %s\n", cnt, head->name);
//        if(RelocateElfREL(maplib, local_maplib, bindnow, head, cnt, (Elf64_Rel *)(head->rel + head->delta)))
///            return -1;
    }
    if(head->rela) {
        int cnt = head->relasz / head->relaent;
        DumpRelATable(head, cnt, (Elf64_Rela *)(head->rela + head->delta), "RelA");
        printf_dump(LOG_DEBUG, "Applying %d Relocation(s) with Addend for %s\n", cnt, head->name);
        if(RelocateElfRELA(maplib, local_maplib, bindnow, head, cnt, (Elf64_Rela *)(head->rela + head->delta), NULL))
            return -1;
    }
    head->had_RelocateElf = 1;
    return 0;
}

void CalcStack(elfheader_t* elf, uint64_t* stacksz, size_t* stackalign)
{
    if(*stacksz < elf->stacksz)
        *stacksz = elf->stacksz;
    if(*stackalign < elf->stackalign)
        *stackalign = elf->stackalign;
}

void AddSymbols(lib_t *maplib, kh_mapsymbols_t* mapsymbols, kh_mapsymbols_t* weaksymbols, kh_mapsymbols_t* localsymbols, elfheader_t* h)
{
#if !defined(LATX_RELOCATION_SAVE_SYMBOLS)
    return;
#endif
    if(relocation_dump && h->DynSym) DumpDynSym(h);
    int libcef = (strstr(h->name, "libcef.so"))?1:0;
    //libcef.so is linked with tcmalloc staticaly, but this cannot be easily supported in box64, so hacking some "unlink" here
    const char* avoid_libcef[] = {"malloc", "realloc", "free", "calloc", "cfree",
        "__libc_malloc", "__libc_calloc", "__libc_free", "__libc_memallign", "__libc_pvalloc",
        "__libc_realloc", "__libc_valloc", "__posix_memalign",
        "valloc", "pvalloc", "posix_memalign", "malloc_stats", "malloc_usable_size",
        /*"mallopt",*/ "localtime_r",
        //c++ symbol from libstdc++ too
        //"_ZnwmRKSt9nothrow_t", "_ZdaPv",    // operator new(unsigned long, std::nothrow_t const&), operator delete[](void*)
        //"_Znwm", "_ZdlPv", "_Znam",         // operator new(unsigned long), operator delete(void*), operator new[](unsigned long)
        //"_ZnwmSt11align_val_t", "_ZnwmSt11align_val_tRKSt9nothrow_t",   // operator new(unsigned long, std::align_val_t)
        //"_ZnamSt11align_val_t", "_ZnamSt11align_val_tRKSt9nothrow_t",   // operator new[](unsigned long, std::align_val_t)
        //"_ZdlPvRKSt9nothrow_t", "_ZdaPvSt11align_val_tRKSt9nothrow_t",  // more delete operators
        //"_ZdlPvmSt11align_val_t", "_ZdaPvRKSt9nothrow_t",
        //"_ZdaPvSt11align_val_t", "_ZdlPvSt11align_val_t",
    };
    printf_log(LOG_INFO, "Will look for Symbol to add in SymTable(%zu)\n", h->numSymTab);
    for (size_t i=0; i<h->numSymTab; ++i) {
        const char * symname = h->StrTab+h->SymTab[i].st_name;
        int bind = ELF64_ST_BIND(h->SymTab[i].st_info);
        int type = ELF64_ST_TYPE(h->SymTab[i].st_info);
        int vis = h->SymTab[i].st_other&0x3;
        size_t sz = h->SymTab[i].st_size;
        if((type==STT_OBJECT || type==STT_FUNC || type==STT_COMMON || type==STT_TLS  || type==STT_NOTYPE) 
        && (vis==STV_DEFAULT || vis==STV_PROTECTED) && (h->SymTab[i].st_shndx!=0)) {
            if(sz && strstr(symname, "@@")) {
                char symnameversionned[strlen(symname)+1];
                strcpy(symnameversionned, symname);
                // extact symname@@vername
                char* p = strchr(symnameversionned, '@');
                *p=0;
                p+=2;
                symname = AddDictionnary(my_context->versym, symnameversionned);
                const char* vername = AddDictionnary(my_context->versym, p);
                if((bind==STB_GNU_UNIQUE /*|| (bind==STB_GLOBAL && type==STT_FUNC)*/) && FindGlobalSymbol(maplib, symname, 2, p))
                    continue;
                uintptr_t offs = (type==STT_TLS)?h->SymTab[i].st_value:(h->SymTab[i].st_value + h->delta);
                printf_log(LOG_INFO, "Adding Default Versionned Symbol(bind=%s) \"%s@%s\" with offset=%p sz=%zu\n", (bind==STB_LOCAL)?"LOCAL":((bind==STB_WEAK)?"WEAK":"GLOBAL"), symname, vername, (void*)offs, sz);
                if(bind==STB_LOCAL)
                    AddSymbol(localsymbols, symname, offs, sz, 2, vername);
                else    // add in local and global map 
                    if(bind==STB_WEAK) {
                        AddSymbol(weaksymbols, symname, offs, sz, 2, vername);
                    } else {
                        AddSymbol(mapsymbols, symname, offs, sz, 2, vername);
                    }
            } else {
                int to_add = 1;
                if(libcef) {
                    if(strstr(symname, "_Zn")==symname || strstr(symname, "_Zd")==symname)
                        to_add = 0;
                    for(int j=0; j<sizeof(avoid_libcef)/sizeof(avoid_libcef[0]) && to_add; ++j)
                        if(!strcmp(symname, avoid_libcef[j]))
                            to_add = 0;
                }
                if(!to_add || (bind==STB_GNU_UNIQUE && FindGlobalSymbol(maplib, symname, -1, NULL)))
                    continue;
                uintptr_t offs = (type==STT_TLS)?h->SymTab[i].st_value:(h->SymTab[i].st_value + h->delta);
                printf_log(LOG_INFO, "Adding Symbol(bind=%s,type=%s) \"%s\" with offset=%p sz=%zu\n", (bind==STB_LOCAL)?"LOCAL":((bind==STB_WEAK)?"WEAK":"GLOBAL"),(type==STT_OBJECT)?"OBJECT":((type==STT_FUNC)?"FUNC":"UNKWON"), symname, (void*)offs, sz);
                if(bind==STB_LOCAL)
                    AddSymbol(localsymbols, symname, offs, sz, 1, NULL);
                else    // add in local and global map 
                    if(bind==STB_WEAK) {
                        AddSymbol(weaksymbols, symname, offs, sz, 1, NULL);
                    } else {
                        AddSymbol(mapsymbols, symname, offs, sz, 1, NULL);
                    }
            }
        }
    }
    
    printf_log(LOG_INFO, "Will look for Symbol to add in DynSym (%zu)\n", h->numDynSym);
    for (size_t i=0; i<h->numDynSym; ++i) {
        const char * symname = h->DynStr+h->DynSym[i].st_name;
        int bind = ELF64_ST_BIND(h->DynSym[i].st_info);
        int type = ELF64_ST_TYPE(h->DynSym[i].st_info);
        int vis = h->DynSym[i].st_other&0x3;
        if((type==STT_OBJECT || type==STT_FUNC || type==STT_COMMON || type==STT_TLS  || type==STT_NOTYPE) 
        && (vis==STV_DEFAULT || vis==STV_PROTECTED) && (h->DynSym[i].st_shndx!=0 && h->DynSym[i].st_shndx<=65521)) {
            uintptr_t offs = (type==STT_TLS)?h->DynSym[i].st_value:(h->DynSym[i].st_value + h->delta);
            size_t sz = h->DynSym[i].st_size;
            int version = h->VerSym?((Elf64_Half*)((uintptr_t)h->VerSym+h->delta))[i]:-1;
            if(version!=-1) version &= 0x7fff;
            const char* vername = GetSymbolVersion(h, version);
            int to_add = 1;
            if(libcef) {
                if(strstr(symname, "_Zn")==symname || strstr(symname, "_Zd")==symname)
                    to_add = 0;
                for(int j=0; j<sizeof(avoid_libcef)/sizeof(avoid_libcef[0]) && to_add; ++j)
                    if(!strcmp(symname, avoid_libcef[j]))
                        to_add = 0;
            }
            if(!to_add || (bind==STB_GNU_UNIQUE && FindGlobalSymbol(maplib, symname, version, vername)))
                continue;
            printf_log(LOG_INFO, "Adding Versionned Symbol(bind=%s) \"%s\" (ver=%d/%s) with offset=%p sz=%zu\n", (bind==STB_LOCAL)?"LOCAL":((bind==STB_WEAK)?"WEAK":"GLOBAL"), symname, version, vername?vername:"(none)", (void*)offs, sz);
            if(bind==STB_LOCAL)
                AddSymbol(localsymbols, symname, offs, sz, version, vername);
            else // add in local and global map 
                if(bind==STB_WEAK) {
                    AddSymbol(weaksymbols, symname, offs, sz, version, vername);
                } else {
                    AddWeakSymbol(mapsymbols, symname, offs, sz, version?version:1, vername);
                }
        }
    }
    
}

/*
$ORIGIN – Provides the directory the object was loaded from. This token is typical
used for locating dependencies in unbundled packages. For more details of this
token expansion, see “Locating Associated Dependencies”
$OSNAME – Expands to the name of the operating system (see the uname(1) man
page description of the -s option). For more details of this token expansion, see
“System Specific Shared Objects”
$OSREL – Expands to the operating system release level (see the uname(1) man
page description of the -r option). For more details of this token expansion, see
“System Specific Shared Objects”
$PLATFORM – Expands to the processor type of the current machine (see the
uname(1) man page description of the -i option). For more details of this token
expansion, see “System Specific Shared Objects”
*/
extern const char *interp_prefix;
int LoadNeededLibs(elfheader_t* h, lib_t *maplib, needed_libs_t* neededlibs, library_t *deplib, int local, int bindnow, box64context_t *box64)
{
    if (!h->latx_hasfix) return 1;
    if(relocation_dump) DumpDynamicRPath(h);
    // update RPATH first
    for (size_t i=0; i<h->numDynamic; ++i)
        if(h->Dynamic[i].d_tag==DT_RPATH || h->Dynamic[i].d_tag==DT_RUNPATH) {
            char *rpathref = h->DynStrTab+h->delta+h->Dynamic[i].d_un.d_val;
            char* rpath = rpathref;
            while(strstr(rpath, "$ORIGIN")) {
                char* origin = box_strdup(h->path);
                char* p = strrchr(origin, '/');
                if(p) *p = '\0';    // remove file name to have only full path, without last '/'
                char* tmp = (char*)box_calloc(1, strlen(rpath)-strlen("$ORIGIN")+strlen(origin)+1);
                p = strstr(rpath, "$ORIGIN");
                memcpy(tmp, rpath, p-rpath);
                strcat(tmp, origin);
                strcat(tmp, p+strlen("$ORIGIN"));
                if(rpath!=rpathref)
                    box_free(rpath);
                rpath = tmp;
                box_free(origin);
            }
            while(strstr(rpath, "${ORIGIN}")) {
                char* origin = box_strdup(h->path);
                char* p = strrchr(origin, '/');
                if(p) *p = '\0';    // remove file name to have only full path, without last '/'
                char* tmp = (char*)box_calloc(1, strlen(rpath)-strlen("${ORIGIN}")+strlen(origin)+1);
                p = strstr(rpath, "${ORIGIN}");
                memcpy(tmp, rpath, p-rpath);
                strcat(tmp, origin);
                strcat(tmp, p+strlen("${ORIGIN}"));
                if(rpath!=rpathref)
                    box_free(rpath);
                rpath = tmp;
                box_free(origin);
            }
            while(strstr(rpath, "${PLATFORM}")) {
                char* platform = box_strdup("x86_64");
                char* p = strrchr(platform, '/');
                if(p) *p = '\0';    // remove file name to have only full path, without last '/'
                char* tmp = (char*)box_calloc(1, strlen(rpath)-strlen("${PLATFORM}")+strlen(platform)+1);
                p = strstr(rpath, "${PLATFORM}");
                memcpy(tmp, rpath, p-rpath);
                strcat(tmp, platform);
                strcat(tmp, p+strlen("${PLATFORM}"));
                if(rpath!=rpathref)
                    box_free(rpath);
                rpath = tmp;
                box_free(platform);
            }
            if(strchr(rpath, '$')) {
                printf_log(LOG_INFO, "BOX64: Warning, RPATH with $ variable not supported yet (%s)\n", rpath);
            } else {
                char latxpath [PATH_MAX] = {0};
                snprintf(latxpath , PATH_MAX, "%s%s:%s", strlen(interp_prefix)?interp_prefix:"/usr/gnemul/latx-x86_64", rpath,rpath);
                printf_log(LOG_INFO, "Prepending path \"%s\" to BOX64_LD_LIBRARY_PATH\n", latxpath);
                PrependList(&box64->box64_ld_lib, latxpath, 1);
            }
            if(rpath!=rpathref)
                box_free(rpath);
        }

    if(!h->neededlibs && neededlibs)
        h->neededlibs = neededlibs;

    DumpDynamicNeeded(h);
    int cnt = 0;
    for (int i=0; i<h->numDynamic; ++i)
        if(h->Dynamic[i].d_tag==DT_NEEDED)
            ++cnt;
    const char* nlibs[cnt];
    int j=0;
    for (int i=0; i<h->numDynamic; ++i)
        if(h->Dynamic[i].d_tag==DT_NEEDED) {
            if (strstr(h->DynStrTab+h->delta+h->Dynamic[i].d_un.d_val, "ld-linux-x86-64.so.2")) {
                cnt--;
                continue;
            }
            nlibs[j++] = h->DynStrTab+h->delta+h->Dynamic[i].d_un.d_val;
        }

    // TODO: Add LD_LIBRARY_PATH and RPATH handling
    if(AddNeededLib(maplib, neededlibs, deplib, local, bindnow, nlibs, cnt, box64)) {
        printf_log(LOG_INFO, "Error loading one of needed lib\n");
        if(!allow_missing_libs)
            return 1;   //error...
    }
    return 0;
}

void RunElfInit(elfheader_t* h)
{
}

EXPORTDYN
void RunDeferedElfInit(void)
{
}

void RunElfFini(elfheader_t* h)
{
}

uintptr_t GetElfInit(elfheader_t* h)
{
    return h->initentry + h->delta;
}
uintptr_t GetElfFini(elfheader_t* h)
{
    return h->finientry + h->delta;
}

void* GetBaseAddress(elfheader_t* h)
{
    return h->memory;
}

void* GetElfDelta(elfheader_t* h)
{
    return (void*)h->delta;
}

uint32_t GetBaseSize(elfheader_t* h)
{
    return h->memsz;
}

int IsAddressInElfSpace(const elfheader_t* h, uintptr_t addr)
{
    if(!h)
        return 0;
    //Todo: multiblock_ need to be init
    for(int i=0; i<h->multiblock_n; ++i) {
        uintptr_t base = h->multiblock_offs[i];
        uintptr_t end = h->multiblock_offs[i] + h->multiblock_size[i] - 1;
        if(addr>=base && addr<=end)
            return 1;
    }
    return 0;
}

elfheader_t* FindElfAddress(box64context_t *context, uintptr_t addr)
{
    for (int i=0; i<context->elfsize; ++i)
        if(IsAddressInElfSpace(context->elfs[i], addr))
            return context->elfs[i];
    return NULL;
}

const char* FindNearestSymbolName(elfheader_t* h, void* p, uintptr_t* start, uint64_t* sz)
{
    uintptr_t addr = (uintptr_t)p;

    uint32_t distance = 0x7fffffff;
    const char* ret = NULL;
    uintptr_t s = 0;
    uint64_t size = 0;
    if(!h || h->fini_done)
        return ret;

    for (size_t i=0; i<h->numSymTab && distance!=0; ++i) {
        const char * symname = h->StrTab+h->SymTab[i].st_name;
        uintptr_t offs = h->SymTab[i].st_value + h->delta;

        if(offs<=addr) {
            if(distance>addr-offs) {
                distance = addr-offs;
                ret = symname;
                s = offs;
                size = h->SymTab[i].st_size;
            }
        }
    }
    for (size_t i=0; i<h->numDynSym && distance!=0; ++i) {
        const char * symname = h->DynStr+h->DynSym[i].st_name;
        uintptr_t offs = h->DynSym[i].st_value + h->delta;

        if(offs<=addr) {
            if(distance>addr-offs) {
                distance = addr-offs;
                ret = symname;
                s = offs;
                size = h->DynSym[i].st_size;
            }
        }
    }

    if(start)
        *start = s;
    if(sz)
        *sz = size;

    return ret;
}

const char* VersionnedName(const char* name, int ver, const char* vername)
{
    if(ver==-1)
        return name;
    const char *v=NULL;
    if(ver==0)
        v="";
    if(ver==1)
        v="*";
    if(!v && !vername)
        return name;
    if(ver>1)
        v = vername;
    char buf[strlen(name)+strlen(v)+1+1];
    strcpy(buf, name);
    strcat(buf, "@");
    strcat(buf, v);
    return AddDictionnary(my_context->versym, buf);
}

int SameVersionnedSymbol(const char* name1, int ver1, const char* vername1, const char* name2, int ver2, const char* vername2)
{
    if(strcmp(name1, name2))    //name are different, no need to go further
        return 0;
    if(ver1==-1 || ver2==-1)    // don't check version, so ok
        return 1;
    if(ver1==ver2 && ver1<2)    // same ver (local or global), ok
        return 1;
    if(ver1==0 || ver2==0)  // one is local, the other is not, no match
        return 0;
    if(ver1==1 || ver2==1)  // one if global, ok
        return 1;
    if(!strcmp(vername1, vername2))  // same vername
        return 1;
    return 0;
}

void* GetDynamicSection(elfheader_t* h)
{
    if(!h)
        return NULL;
    return h->Dynamic;
}

typedef struct search_symbol_s{
    const char* name;
    void*       addr;
    void*       lib;
} search_symbol_t;

static int dl_iterate_phdr_findsymbol(struct dl_phdr_info* info, size_t size, void* data)
{
    search_symbol_t* s = (search_symbol_t*)data;

    for(int j = 0; j<info->dlpi_phnum; ++j) {
        if (info->dlpi_phdr[j].p_type == PT_DYNAMIC) {
            //ElfW(Sym)* sym = NULL;
            //ElfW(Word) sym_cnt = 0;
            ElfW(Verdef)* verdef = NULL;
            ElfW(Word) verdef_cnt = 0;
            char *strtab = NULL;
            ElfW(Dyn)* dyn = (ElfW(Dyn)*)(info->dlpi_addr +  info->dlpi_phdr[j].p_vaddr); //Dynamic Section
            // grab the needed info
            while(dyn->d_tag != DT_NULL) {
                switch(dyn->d_tag) {
                    case DT_STRTAB:
                        strtab = (char *)(dyn->d_un.d_ptr);
                        break;
                    case DT_VERDEF:
                        verdef = (ElfW(Verdef)*)(info->dlpi_addr +  dyn->d_un.d_ptr);
                        break;
                    case DT_VERDEFNUM:
                        verdef_cnt = dyn->d_un.d_val;
                        break;
                }
                ++dyn;
            }
            if(strtab && verdef && verdef_cnt) {
                if((uintptr_t)strtab < (uintptr_t)info->dlpi_addr) // this test is need for linux-vdso on PI and some other OS (looks like a bug to me)
                    strtab=(char*)((uintptr_t)strtab + info->dlpi_addr);
                // Look fr all defined versions now
                ElfW(Verdef)* v = verdef;
                while(v) {
                    ElfW(Verdaux)* vda = (ElfW(Verdaux)*)(((uintptr_t)v) + v->vd_aux);
                    if(v->vd_version>0 && !v->vd_flags)
                        for(int i=0; i<v->vd_cnt; ++i) {
                            const char* vername = (strtab+vda->vda_name);
                            if(vername && vername[0] && (s->addr = dlvsym(s->lib, s->name, vername))) {
                                printf_log(/*LOG_DEBUG*/LOG_INFO, "Found symbol with version %s, value = %p\n", vername, s->addr);
                                return 1;   // stop searching
                            }
                            vda = (ElfW(Verdaux)*)(((uintptr_t)vda) + vda->vda_next);
                        }
                    v = v->vd_next?(ElfW(Verdef)*)((uintptr_t)v + v->vd_next):NULL;
                }
            }
        }
    }
    return 0;
}

void* GetNativeSymbolUnversionned(void* lib, const char* name)
{
    // try to find "name" in loaded elf, whithout checking for the symbol version (like dlsym, but no version check)
    search_symbol_t s;
    s.name = name;
    s.addr = NULL;
    if(lib) 
        s.lib = lib;
    else 
        s.lib = my_context->box64lib;
    printf_log(LOG_INFO, "Look for %s in loaded elfs\n", name);
    dl_iterate_phdr(dl_iterate_phdr_findsymbol, &s);
    return s.addr;
}

static int64_t Pop64(CPUX86State *cpu)
{
    uint64_t* st = ((uint64_t*)(cpu->regs[R_ESP]));
    cpu->regs[R_ESP] += 8;

    return *st;
}
static void Push64(CPUX86State *cpu, uint64_t v)
{
    cpu->regs[R_ESP] -= 8;
    *((uint64_t*)cpu->regs[R_ESP]) = v;

}
uintptr_t pltResolver = ~0LL;
uintptr_t dl_runtime_resolver = ~0LL;
uintptr_t link_map_obj=0;
#ifdef CONFIG_LATX_KZT
static void KztLazyBindingCompleteResolver(void)
{
    CPUX86State *cpu = (CPUX86State *)lsenv->cpu_state;
    kzt_lazy_binding_pending_t *pending =
        &cpu->kzt_lazy_binding_pending;
    uintptr_t original_return = cpu->kzt_lazy_original_return;
    uintptr_t slot_addr = pending->slot_addr;
    char symbol[KZT_LAZY_BINDING_SYMBOL_MAX];
    kzt_lazy_binding_result_t result;

    (void)slot_addr;

    symbol[0] = '\0';
    if (pending->symbol) {
        strncpy(symbol, pending->symbol, sizeof(symbol) - 1);
        symbol[sizeof(symbol) - 1] = '\0';
    }
    if (pending->armed) {
        if (option_kzt_lazy_diagnostics) {
            kzt_lazy_binding_pending_t pending_snapshot = *pending;
            kzt_lazy_diagnostic_emit_result_t diagnostic_result;

            pending_snapshot.symbol = pending->symbol ?
                pending_snapshot.symbol_storage : NULL;
            pending_snapshot.version = pending->version ?
                pending_snapshot.version_storage : NULL;
            (void)kzt_production_lazy_complete(
                (void *)pending->context_id, pending, &result);
            (void)kzt_lazy_diagnostics_emit_production(
                &pending_snapshot, &result, &diagnostic_result);
        } else {
            (void)kzt_production_lazy_complete(
                (void *)pending->context_id, pending, &result);
        }
        printf_log(LOG_DEBUG,
                   "KZT: lazy complete status=%d reason=%d slot=%p "
                   "before=%p after=%p sym=%s\n",
                   result.status, result.reason,
                   (void *)slot_addr,
                   (void *)result.slot_before, (void *)result.slot_after,
                   symbol[0] ? symbol : "(none)");
    }
    kzt_lazy_binding_cancel(pending);
    cpu->kzt_lazy_original_return = 0;
    Push64(cpu, original_return);
}

typedef struct kzt_plt_resolver_production_state {
    elfheader_t *head;
    uintptr_t slot_addr;
    uintptr_t unresolved_stub;
    const char *symbol;
    const char *version;
    long addend;
} kzt_plt_resolver_production_state_t;

static int kzt_plt_resolver_lookup_source(
    uintptr_t object_head, kzt_plt_resolver_source_t *source, void *opaque)
{
    kzt_plt_resolver_production_state_t *state = opaque;
    kzt_guest_registry_t *registry = KztGuestRegistryForContext(my_context);
    kzt_guest_object_snapshot_t *snapshot = NULL;
    kzt_guest_lazy_resolver_t resolver;
    int result = -1;

    if (!state || !state->head || object_head != (uintptr_t)state->head ||
        !source || !state->head->self_link_map ||
        kzt_guest_registry_find_by_link_map(
            registry, state->head->self_link_map, &snapshot) != 0 ||
        !snapshot || snapshot->namespace_id.status != KZT_GUEST_FIELD_OK ||
        snapshot->namespace_id.value != 0 ||
        kzt_guest_registry_find_lazy_resolver(
            registry, state->head->self_link_map, snapshot->generation, 0,
            &resolver) != 0 ||
        resolver.guest_link_map != state->head->self_link_map) {
        goto out;
    }
    *source = (kzt_plt_resolver_source_t) {
        .enabled = my_context->kzt_lazy_completion_bridge != 0,
        .context_id = (uintptr_t)my_context,
        .object_head = object_head,
        .source_link_map = state->head->self_link_map,
        .source_generation = snapshot->generation,
        .namespace_id = snapshot->namespace_id.value,
        .namespace_kind = KZT_GUEST_LIBRARY_NAMESPACE_MAIN,
        .slot_addr = state->slot_addr,
        .unresolved_stub = state->unresolved_stub,
        .symbol = state->symbol,
        .version = state->version,
        .addend = state->addend,
        .guest_resolver = resolver.guest_resolver,
    };
    result = 0;
out:
    kzt_guest_object_snapshot_free(snapshot);
    return result;
}

static int kzt_plt_resolver_begin_lazy_binding(
    const kzt_lazy_binding_begin_request_t *request,
    kzt_lazy_binding_pending_t *pending,
    kzt_lazy_binding_result_t *result, void *opaque)
{
    (void)opaque;
    return kzt_lazy_binding_begin(request, pending, result);
}
#endif
void PltResolver(void)
{
    CPUX86State *cpu = (CPUX86State*)lsenv->cpu_state;
    uintptr_t addr = Pop64(cpu);
    int slot = (int)Pop64(cpu);
    elfheader_t *h = (elfheader_t*)addr;
    printf_log(LOG_INFO, "PltResolver: Addr=%p, Slot=%d Return=%p: elf is %s (VerSym=%p)\n", (void*)addr, slot, *(void**)(cpu->regs[R_ESP]), h->name, h->VerSym);

    Elf64_Rela * rel = (Elf64_Rela *)(h->jmprel + h->delta) + slot;
    Elf64_Sym *sym = &h->DynSym[ELF64_R_SYM(rel->r_info)];
 #if defined(CONFIG_LATX_KZT) && defined(CONFIG_LATX_DEBUG)
    int bind = ELF64_ST_BIND(sym->st_info);
 #endif
    const char* symname = SymName(h, sym);
    int version = h->VerSym?((Elf64_Half*)((uintptr_t)h->VerSym+h->delta))[ELF64_R_SYM(rel->r_info)]:-1;
    if(version!=-1) version &= 0x7fff;
    const char* vername = GetSymbolVersion(h, version);
    uint64_t *p = (uint64_t*)(rel->r_offset + h->delta);
    uintptr_t offs = 0;
    uintptr_t end = 0;
    library_t *resolved_provider = NULL;

    (void)bind;

#ifdef CONFIG_LATX_KZT
    if (option_kzt_lazy_diagnostics) {
        printf_kzt_registry_diagnostics(
            "kzt_lazy_resolver_entry symbol=%s slot=%p source=%p\n",
            symname ? symname : "(none)", (void *)p,
            (void *)h->self_link_map);
    }
    if (option_kzt || wine_option_kzt) {
        kzt_plt_resolver_production_state_t state = {
            .head = h,
            .slot_addr = (uintptr_t)p,
            .unresolved_stub = p ?
                __atomic_load_n((uintptr_t *)p, __ATOMIC_ACQUIRE) : 0,
            .symbol = symname,
            .version = vername,
            .addend = rel->r_addend,
        };
        kzt_plt_resolver_runtime_ops_t ops = {
            .lookup_source = kzt_plt_resolver_lookup_source,
            .begin_lazy_binding = kzt_plt_resolver_begin_lazy_binding,
            .pending = &cpu->kzt_lazy_binding_pending,
            .completion_bridge = my_context->kzt_lazy_completion_bridge,
            .original_return = &cpu->kzt_lazy_original_return,
            .opaque = &state,
        };
        kzt_plt_resolver_enter_result_t enter_result;

        if (kzt_plt_resolver_enter(cpu, &ops, &enter_result) == 0 &&
            enter_result.status != KZT_PLT_RESOLVER_LEGACY_FRAME_RESTORED) {
            return;
        }
    }
#endif

    (void)Pop64(cpu);
    (void)Pop64(cpu);

    library_t* lib = h->lib;
    lib_t* local_maplib = GetMaplib(lib);
    GetGlobalSymbolStartEndWithProvider(
        my_context->maplib, symname, &offs, &end, h, version, vername,
        &resolved_provider);
    if(!offs && !end && local_maplib) {
        GetGlobalSymbolStartEndWithProvider(
            local_maplib, symname, &offs, &end, h, version, vername,
            &resolved_provider);
    }
    if(!offs && !end && !version)
        GetGlobalSymbolStartEndWithProvider(
            my_context->maplib, symname, &offs, &end, h, -1, NULL,
            &resolved_provider);

    if (!offs) {
//        printf_log(LOG_INFO, "Error: PltResolver: Symbol %s(ver %d: %s%s%s) not found, cannot apply R_X86_64_JUMP_SLOT %p (%p) in %s\n", symname, version, symname, vername?"@":"", vername?vername:"", p, *(void**)p, h->name);
        //return to __dl_runtime_resolver
        Push64(cpu, slot);
        Push64(cpu, h->self_link_map);
        Push64(cpu, dl_runtime_resolver);
        return;
    } else {
        offs = (uintptr_t)getAlternate((void*)offs);
        if(p) {
            uintptr_t slot_observation = (uintptr_t)(*p);
            uintptr_t legacy_target = offs;
#ifdef CONFIG_LATX_KZT
            if (option_kzt || wine_option_kzt) {
                kzt_jump_slot_route_result_t route_result;

                if (kzt_production_jump_slot_route(
                        my_context, resolved_provider, legacy_target, h,
                        1, slot, rel, p,
                    slot_observation, 1,
                        ELF64_R_SYM(rel->r_info), symname,
                        vername, 0, 0, legacy_target, &route_result) == 0 &&
                    route_result.status ==
                        KZT_JUMP_SLOT_ROUTE_NATIVE_APPLIED) {
                    printf_kzt_registry_diagnostics(
                        "KZT lazy route applied slot=%p observed=%p "
                        "legacy=%p selected=%p symbol=%s\n",
                        p, (void *)slot_observation, (void*)legacy_target,
                        (void *)route_result.selected_target,
                        symname ? symname : "(none)");
                    Push64(cpu, route_result.selected_target);
                    return;
                }
                if (route_result.status ==
                        KZT_JUMP_SLOT_ROUTE_GUEST_PRESERVED ||
                    route_result.status ==
                        KZT_JUMP_SLOT_ROUTE_CAS_MISMATCH) {
                    Push64(cpu, route_result.final_value);
                    return;
                }
            }
#endif
            printf_log(LOG_INFO, "            Apply %s R_X86_64_JUMP_SLOT %p with sym=%s(ver %d: %s%s%s) (%p -> %p / %s)\n", (bind==STB_LOCAL)?"Local":"Global", p, symname, version, symname, vername?"@":"", vername?vername:"",*(void**)p, (void*)offs, ElfName(FindElfAddress(my_context, offs)));
            *p = offs;
        } else {
            printf_log(LOG_INFO, "PltResolver: Warning, Symbol %s(ver %d: %s%s%s) found, but Jump Slot Offset is NULL \n", symname, version, symname, vername?"@":"", vername?vername:"");
        }
        //next_tb is the onebridge of the function
        Push64(cpu, offs);
    }
}
