#define _GNU_SOURCE
#include <fcntl.h>

#if __has_include(<elf.h>)
#  include <elf.h>
#elif __has_include(<sys/elf.h>)
#  include <sys/elf.h>
#else
#  error "Need ELF header."
#endif

#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <string.h>
#include <stddef.h>
#include <assert.h>

#define IS_NOT_ELF(ehdr) (                           \
    ((ehdr)->e_ident[EI_DATA] != ELFDATA2LSB         \
      && (ehdr)->e_ident[EI_DATA] != ELFDATA2MSB)    \
    || ehdr->e_ident[EI_VERSION] != EV_CURRENT       \
    || ehdr->e_ehsize != sizeof(Elf64_Ehdr)    \
    || ehdr->e_shentsize != sizeof(Elf64_Shdr) \
)

enum woodyStatus {
    WOODY_STATUS_OK = 0,
    ERR_CORRUPTED_FILE,
    ERR_EXTLIB_CALL,
    WOODY_MAX_ERRORS
};

static const char *errors[WOODY_MAX_ERRORS] = {
    [WOODY_STATUS_OK]    = "",
    [ERR_CORRUPTED_FILE] = "Input file format is either not ELF or corrupted",
    [ERR_EXTLIB_CALL] = "An external library call failed during execution"
};

#define LOG_ERRNO() \
    if (errno!=0) { \
        LOG_ERR("%s: %s", errors[ERR_EXTLIB_CALL], strerror(errno)); \
    }

#define TRY_RET(COMMAND) { \
    int __ret=(COMMAND); \
    if (unlikely(__ret!=WOODY_STATUS_OK)) { \
        if (__ret==ERR_EXTLIB_CALL) { \
            LOG_ERRNO(); \
        } else { \
            LOG_ERR("%s", errors[__ret]); \
        } \
    } \
}

#define unlikely(x)     __builtin_expect(!!(x), 0)
#define LOG_ERR(FMT,...) \
    fprintf(stderr, "ERR|%s:%d|%s|" FMT "\n", __FILE__, __LINE__, __func__, ##__VA_ARGS__);

/* alignment MUST be a power of 2 */
#define ALIGNED_SIZE(phdr) ALIGN((phdr)->p_filesz, (phdr)->p_align)
#define ALIGN(addr, alignment) (((addr)+(alignment)-1)&~((alignment)-1))

typedef struct woodyCtx {
    Elf64_Phdr *phtab; /* Primer elemento del array de program headers */
    Elf64_Ehdr *elf_hdr;
    Elf64_Phdr *phdr; /* PT_PHDR*/
    Elf64_Phdr *text_phdr; /* PT_LOAD con PF_X|PF_R */
    Elf64_Phdr *new_phdr; /* Nuevo PT_LOAD */
    uint8_t key[32];
    Elf64_Shdr *text_shdr;
    Elf64_Addr initial_entrypoint;
    Elf64_Xword text_len;
} woodyCtx;


static int _write(int fd, const void *buf, size_t len) {

    size_t total_written = 0;
    const char *p = (const char *)buf;

    while (total_written < len) {
        ssize_t bytes_written = write(fd, p + total_written, len - total_written);
        if (bytes_written == -1) {
            if (errno == EINTR) {
                continue;
            }
            return ERR_EXTLIB_CALL;
        }
        if (bytes_written == 0) {
            break;
        }
        total_written += bytes_written;
    }

    return WOODY_STATUS_OK;
}

/* See https://refspecs.linuxfoundation.org/elf/gabi4+/ch4.eheader.html#elfid */
static size_t get_ehdr_e_shnum(void* map, Elf64_Ehdr* ehdr) {
    if (ehdr->e_shnum >= SHN_LORESERVE) {
        return ((Elf64_Shdr *)(map + ehdr->e_shoff))->sh_size;
    }
    return ehdr->e_shnum;
}

/*
 * Calcula cuanto mide el fichero elf buscando cual es el offset + tamaño
 * más grande que hay. De esta forma el orden dentro del fichero nos da igual.
 * See https://refspecs.linuxfoundation.org/elf/gabi4+/ch4.intro.html
 */
static int get_elf_size(void *map, Elf64_Ehdr *ehdr, size_t actual_size, size_t *computed_size) {

    size_t total = 0;
    Elf64_Off phoff = ehdr->e_phoff;
    Elf64_Off shoff = ehdr->e_shoff;
    Elf64_Half shentsize = ehdr->e_shentsize;
    Elf64_Half phentsize = ehdr->e_phentsize;
    size_t shnum = get_ehdr_e_shnum(map, ehdr);
    Elf64_Half phnum = ehdr->e_phnum;

    /* Most programs should be ok with this block */
    if (phoff < shoff) {
        total = shoff + shnum * shentsize;
    } else {
        total =  phoff + phnum * phentsize;
    }
    /* BUT this is not forbidden in the standard */
    for (size_t i = 0; i < phnum; i++) {
        if (phoff + i * phentsize > actual_size) {
            return ERR_CORRUPTED_FILE;
        }
        Elf64_Phdr *phent = map + phoff + i * phentsize;
        Elf64_Off p_offset = phent->p_offset;
        Elf64_Xword p_filesz = phent->p_filesz;
        if (p_offset + p_filesz > total) {
            total = p_offset + p_filesz;
        }
    }
    for (size_t i = 0; i < shnum; i++) {
        if (shoff + i * shentsize > actual_size) {
            return ERR_CORRUPTED_FILE;
        }
        Elf64_Shdr *shent = map + shoff + i * shentsize;
        Elf64_Off sh_offset = shent->sh_offset;
        Elf64_Xword sh_size = shent->sh_size;
        if (sh_offset + sh_size > total) {
            /* "A section of type SHT_NOBITS may have a non-zero size,
             * but it occupies no space in the file." */
            if (shent->sh_type != SHT_NOBITS ) {
                total = sh_offset + sh_size;
            }
        }
    }
    *computed_size = total;
    return WOODY_STATUS_OK;
}


static int initialize_context(woodyCtx *ctx, void *map, size_t size) {

    ctx->elf_hdr = map;
    Elf64_Shdr *shdr = (Elf64_Shdr *)((char*)map + ctx->elf_hdr->e_shoff);

    if ((size_t)((char*)shdr - (char*)map) > size) {
        return ERR_CORRUPTED_FILE;
    }

    Elf64_Shdr *shstrtab = &shdr[ctx->elf_hdr->e_shstrndx];
    for (int i=0; i < ctx->elf_hdr->e_shnum; i++) {
        Elf64_Shdr *_shdr = &shdr[i];
        if (_shdr->sh_type == SHT_PROGBITS &&
            !strncmp(".text", map+shstrtab->sh_offset+_shdr->sh_name, strlen(".text")+1)) {
            ctx->text_shdr = _shdr;
            break;
        }
    }

    if (!ctx->text_shdr) {
        return ERR_CORRUPTED_FILE;
    }

    ctx->phtab = map + ctx->elf_hdr->e_phoff;
    // Find the .text section
    for (Elf64_Half i = 0; i < ctx->elf_hdr->e_phnum; i++) {
        Elf64_Phdr* phdr = &ctx->phtab[i];
        if (phdr->p_type == PT_LOAD && phdr->p_flags & (PF_R | PF_X)
            /* De estos PT_LOAD pueden haber varios, buscamos el que contiene el .text */
            && phdr->p_offset <= ctx->text_shdr->sh_offset
            && phdr->p_offset + phdr->p_filesz >= ctx->text_shdr->sh_offset + ctx->text_shdr->sh_size) {
            ctx->text_phdr = phdr;
        }
        if (phdr->p_type == PT_PHDR) {
            ctx->phdr = phdr;
        }
    }

    if (!ctx->phdr || !ctx->text_phdr) {
        return ERR_CORRUPTED_FILE;
    }

    ctx->new_phdr->p_type = PT_LOAD;
    ctx->new_phdr->p_flags = (PF_R | PF_X);
    ctx->new_phdr->p_align = ctx->text_phdr->p_align;

    return WOODY_STATUS_OK;
}


/*
 * Crea un Elf64_Phdr de la sección donde insertaremos el shellcode.
 */
static void set_new_program_header(woodyCtx *ctx, size_t size, size_t sz_payload) {

    /* HAcemos que el nuevo phdr esté contenido en la nueva seccion load, si no, falla. */
    ctx->new_phdr->p_filesz = (sizeof(Elf64_Phdr) * (1 + ctx->elf_hdr->e_phnum)) + sz_payload;
    ctx->new_phdr->p_memsz = ctx->new_phdr->p_filesz;
    ctx->new_phdr->p_offset = ALIGN(size, ctx->new_phdr->p_align);

    /* Buscamos la vaddr más alta entre los PT_LOAD. El nuevo PT_LOAD tendrá que estar por encima de estas,
     * para garantizar que no sobreescribimos nada. */
    Elf64_Addr max_vaddr = 0;
    for (Elf64_Half i = 0; i < ctx->elf_hdr->e_phnum; i++) {
        Elf64_Phdr* phdr = &ctx->phtab[i];
        /* Usamos p_memsz en vez de filesz porque p_memsz >= p_filesz, (está en la spec de ELF) */
        if (phdr->p_type == PT_LOAD && phdr->p_vaddr + phdr->p_memsz > max_vaddr ) {
           max_vaddr = ALIGN(phdr->p_vaddr + phdr->p_memsz, phdr->p_align);
        }
    }

    /* Esto debería estar alineado, asumimos que los PT_LOAD tienen todos el mismo align, o que, como mínimo
     * el último tiene el mismo alineamiento que nosotros usamos. */
    ctx->new_phdr->p_vaddr = max_vaddr;
    ctx->new_phdr->p_paddr = ctx->new_phdr->p_vaddr;

    assert(ctx->new_phdr->p_offset % ctx->new_phdr->p_align == ctx->new_phdr->p_vaddr % ctx->new_phdr->p_align);
}


/*
 * Modifica el Elf64_Phdr de tipo PT_PHDR (la program header table) para que apunte donde situaremos la nueva
 * program header table, que tendrá un phdr nuevo, el de nuestra sección con el shellcode.
 * Por razones místicas el program header tiene que ser loadeado también en memoria. Así que la nueva sección,
 * contendrá en su inicio la nueva program header table, y luego, alineado a , el shellcode.
 */
static void patch_phdr(woodyCtx *ctx) {

    size_t original_phtab_size = sizeof(Elf64_Phdr)*(ctx->elf_hdr->e_phnum);

    ctx->phdr->p_offset = ctx->new_phdr->p_offset; // Nuestra nueva seccion contiene al principio la phtab
    ctx->phdr->p_filesz = original_phtab_size;
    ctx->phdr->p_memsz = ctx->phdr->p_filesz;
    /* La vaddr hay que cambiarla para que tenga sentido con el nuevo offset. Sin esto, eplota. */
    ctx->phdr->p_vaddr = ctx->new_phdr->p_vaddr;
    ctx->phdr->p_paddr = ctx->phdr->p_vaddr;

    assert(ctx->phdr->p_offset % ctx->phdr->p_align == ctx->phdr->p_vaddr % ctx->phdr->p_align);

    /* Modificamos el Elf header */
    ctx->elf_hdr->e_phnum += 1;
    ctx->elf_hdr->e_phoff = ctx->phdr->p_offset;
    ctx->initial_entrypoint = ctx->elf_hdr->e_entry;
    ctx->elf_hdr->e_entry = ctx->new_phdr->p_vaddr + original_phtab_size + sizeof(Elf64_Phdr);
}

static int get_random_key(uint8_t *key, size_t key_len) {

    int fd = open("/dev/urandom", O_RDONLY);
    if (fd == -1) {
        return ERR_EXTLIB_CALL;
    }

    /* Si no puedo leer 32 bytes de un fichero algo esta muy muy pocho */
    if (read(fd, key, key_len) != (ssize_t)key_len) {
        return ERR_EXTLIB_CALL;
    }

    return WOODY_STATUS_OK;
}

/* Nota: Cifrar otras secciones del PT_LOAD rompe la carga dinámica en la mayoría de los casos porque puede contener
 * rutinas que se ejecutan antes de ceder el control a e_entry, que es donde nosotros desciframos el código a ejecutar.
 */
static int encrypt_text_section(woodyCtx *ctx, void *map) {

    TRY_RET(get_random_key(ctx->key, sizeof(ctx->key)));

    /* Initial offset of the .text section computed from the entry: */
    char *mem = (char *)map + ctx->text_phdr->p_offset + ctx->initial_entrypoint - ctx->text_phdr->p_vaddr;
    /*           ------------------------------------   ---------------------------------------------------
     *           Inicio del PT_LOAD que contiene .text  Resta de vaddr para saber el offset REAL donde empieza
     *                                                  el entry. Si 2 items pertenecen a un mismo PT_LOAD, los offsets entre
     *                                                  vaddr son los offsets dentro del fichero, pues el chunk entero se carga.
     */
    char *mem_end = (char *)map + ctx->text_shdr->sh_offset + ctx->text_shdr->sh_size;
    ctx->text_len = mem_end - mem;

    /* Ciframos con un simple xor byte a byte */
    for (Elf64_Xword i=0; i < ctx->text_len; i++) {
        mem[i] ^= ctx->key[i&(0xff>>3)];
    }

    /* Cambiamos los permisos del PT_LOAD que contiene el .text para poder descrifrar en la carga */
    ctx->text_phdr->p_flags = (PF_R | PF_W | PF_X);

    return WOODY_STATUS_OK;
}

/* payload_size MUST NOT include the null terminator. */
static void patch_payload(woodyCtx *ctx, char *payload, size_t payload_size) {

    typedef struct payloadPatchData {
        Elf64_Addr ct_start;
        Elf64_Xword ct_size;
        Elf64_Addr shellcode_start;
        uint8_t key[32];
    } payloadPatchData;

    /* Parcheamos el shellcode */
    char *p = &payload[payload_size - sizeof(payloadPatchData)];

    memcpy(p, &ctx->initial_entrypoint, sizeof(((payloadPatchData *)0)->ct_start));
    p += sizeof(((payloadPatchData *)0)->ct_start);

    memcpy(p, &ctx->text_len, sizeof(((payloadPatchData *)0)->ct_size));
    p += sizeof(((payloadPatchData *)0)->ct_size);

    /* La vaddr donde esté el shellcode es el p_vaddr + sizeof(todos los program headers) */
    memcpy(p, &ctx->elf_hdr->e_entry, sizeof(((payloadPatchData *)0)->shellcode_start));
    p += sizeof(((payloadPatchData *)0)->shellcode_start);

    memcpy(p, ctx->key, sizeof(ctx->key));

    char buf[100]={0}, *q=buf;
    q += sprintf(q, "key=");
    for (unsigned long int i=0; i<sizeof(ctx->key); i++) {
        q += sprintf(q, "%02x", ctx->key[i]);
    }
    sprintf(q, "\n");
    printf(buf);
}

static int build_new_elf_file(int fd_new, woodyCtx *ctx, void *map, size_t size, const char *payload, size_t payload_sz) {

    /* Escribimos el contenido inicial del fichero (adecuadamente modificado)*/
    TRY_RET(_write(fd_new, map, size));

    /* Rellenamos el espacio entre el final del fichero y nuestro inicio de seccion, que tiene
     * que estar alineado porque es un PT_LOAD.*/
    char buf[4096]={0};
    TRY_RET(_write(fd_new, buf, ALIGN(size, ctx->new_phdr->p_align) - size));

    TRY_RET(_write(fd_new, ctx->phtab, sizeof(Elf64_Phdr)*(ctx->elf_hdr->e_phnum-1)));

    TRY_RET(_write(fd_new, ctx->new_phdr, sizeof(Elf64_Phdr)));

    TRY_RET(_write(fd_new, payload, payload_sz));

    return WOODY_STATUS_OK;
}

static int do_woody(void* map, size_t size) {

    Elf64_Ehdr *ehdr = map;          /* Elf Header */
    woodyCtx *ctx = &(woodyCtx){0};

    if (size < sizeof(Elf64_Ehdr)) {
        return ERR_CORRUPTED_FILE;
    }

    if (IS_NOT_ELF(ehdr)) {
        return ERR_CORRUPTED_FILE;
    }

    size_t computed_size = 0;
    TRY_RET(get_elf_size(map, ehdr, size, &computed_size));
    if (size != computed_size) {
        return ERR_CORRUPTED_FILE;
    }

    /* Inicializamos en stack el nuevo phdr porque este no va a apuntar a memoria reservada con mmap */
    ctx->new_phdr = &(Elf64_Phdr){0};
    TRY_RET(initialize_context(ctx, map, size));

    int fd_new = open("woody", O_CREAT | O_RDWR, 00744);
    if (fd_new == -1) {
        return ERR_EXTLIB_CALL;
    }

    char payload[]=
    "\x57\x56\x52\xb8\x01\x00\x00\x00\xbf\x01\x00\x00\x00\x48\x8d\x35"
    "\x5a\x00\x00\x00\xba\x0e\x00\x00\x00\x0f\x05\x48\x8d\x0d\xde\xff"
    "\xff\xff\x4c\x8b\x05\x63\x00\x00\x00\x4c\x29\xc1\x4c\x8b\x05\x49"
    "\x00\x00\x00\x49\x01\xc8\x4c\x89\xc6\x48\x89\xf2\x48\x03\x15\x41"
    "\x00\x00\x00\x48\x8d\x0d\x4a\x00\x00\x00\x48\x31\xc0\x48\x39\xd6"
    "\x74\x16\x48\x83\xe0\x1f\x48\x8d\x3c\x01\x44\x8a\x0f\x44\x30\x0e"
    "\x48\xff\xc0\x48\xff\xc6\xeb\xe5\x5a\x5e\x5f\x41\xff\xe0\x2e\x2e"
    "\x2e\x2e\x57\x4f\x4f\x44\x59\x2e\x2e\x2e\x2e\x0a"
    "\x11\x11\x11\x11\x11\x11\x11\x11" // => ciphertext start vaddr
    "\x22\x22\x22\x22\x22\x22\x22\x22" //=> ciphertext size
    "\x33\x33\x33\x33\x33\x33\x33\x33" // => vaddr of the shellcode
    "\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44" // => key
    "\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44";

    // TODO hacer algo con estos magic numbers
    set_new_program_header(ctx, size, sizeof(payload)-1);
    patch_phdr(ctx);
    TRY_RET(encrypt_text_section(ctx, map));
    patch_payload(ctx, payload, sizeof(payload)-1);
    TRY_RET(build_new_elf_file(fd_new, ctx, map, size, payload, sizeof(payload)-1));

    return WOODY_STATUS_OK;
}

void woody_main(char* filename) {

    int fd = -1;
    struct stat st;
    void* map = MAP_FAILED;

    if ((fd = open(filename, O_RDONLY | O_NONBLOCK)) == -1) {
        LOG_ERRNO();
        goto cleanup;
    }
    if (fstat(fd, &st) == -1) {
        LOG_ERRNO();
        goto cleanup;
    }
    if ((map = mmap(NULL, st.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0)) == MAP_FAILED) {
        LOG_ERRNO();
        goto cleanup;
    }
    if (strncmp((const char *)map, ELFMAG, SELFMAG)) {
        LOG_ERR("%s", errors[ERR_CORRUPTED_FILE]);
        goto cleanup;
    }
    switch ((int)((unsigned char *)map)[EI_CLASS]) {
        case ELFCLASS64:
            int ret = do_woody(map, st.st_size);
            if (ret != WOODY_STATUS_OK) {
                LOG_ERR("%s", errors[ret]);
            }
            break;
        default:
            ;
    }

cleanup:

    if (map != MAP_FAILED && munmap(map, st.st_size) == -1) {
        LOG_ERRNO();
    }

    if (fd != -1 && close(fd) == -1) {
        LOG_ERRNO();
    }
}

int main(int argc,char** argv) {

    char filename[4096] = {0};

    for (int i=1; i<argc; i++) {
        if (argv[i]) {
            memcpy(filename, argv[i], strlen(argv[i]));
        }
        woody_main(filename);
    }
    return 0;
}