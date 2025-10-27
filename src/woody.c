#define _GNU_SOURCE
#include <fcntl.h>

#if __has_include(<elf.h>)
#  include <elf.h>
#elif __has_include(<sys/elf.h>)
#  include <sys/elf.h>
#else
#  error "Need ELF header."
#endif

#include "libft/libft.h"
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <string.h>
#include <stddef.h>
#include <assert.h>

#ifdef __woodydebug
void debug_program_header(void* map, Elf64_Half size, Elf64_Phdr* phdr);
#endif

/* Endianness of the binary */
static int end = 0;

#define swap(p) (end == ELFDATA2LSB ? p : \
                    sizeof(p) == 8 ? __builtin_bswap64(p) : \
                    sizeof(p) == 4 ? __builtin_bswap32(p) : \
                                     __builtin_bswap16(p))

#define IS_NOT_ELF(ehdr) (                           \
    ((ehdr)->e_ident[EI_DATA] != ELFDATA2LSB         \
      && (ehdr)->e_ident[EI_DATA] != ELFDATA2MSB)    \
    || ehdr->e_ident[EI_VERSION] != EV_CURRENT       \
    || swap(ehdr->e_ehsize) != sizeof(Elf64_Ehdr)    \
    || swap(ehdr->e_shentsize) != sizeof(Elf64_Shdr) \
)

/* alignment MUST be a power of 2 */
#define ALIGNED_SIZE(phdr) ALIGN((phdr)->p_filesz, (phdr)->p_align)
#define ALIGN(addr, alignment) (((addr)+(alignment)-1)&~((alignment)-1))

typedef struct woodyCtx {
    Elf64_Phdr *phtab; /* Primer elemento del array de program headers */
    Elf64_Ehdr *elf_hdr;
    Elf64_Phdr *phdr; /* PT_PHDR*/
    Elf64_Phdr *text_phdr; /* PT_LOAD con PF_X|PF_R */
    Elf64_Phdr *new_phdr; /* Nuevo PT_LOAD */
} woodyCtx;

/*
 * qsort hace el sort en orden ASCENDENTE 1 implica mayor que, -1 implica menor que.
 *  1: p1->offset  < p2->p_offset
 * -1: p1->offset  > p2->p_offset
 *  0: p1->offset == p2->p_offset
 */
int _compare_elf_phdr(const void* phdr1, const void* phdr2) {
    const Elf64_Phdr* p1 = *(const Elf64_Phdr**)phdr1;
    const Elf64_Phdr* p2 = *(const Elf64_Phdr**)phdr2;
    return (p1->p_offset < p2->p_offset) - (p1->p_offset > p2->p_offset);
}

int initialize_context(woodyCtx *ctx, void *map, size_t size) {

    ctx->elf_hdr = map;
    ctx->phtab = map + ctx->elf_hdr->e_phoff;

    // Find the .text section
    for (Elf64_Half i = 0; i < ctx->elf_hdr->e_phnum; i++) {
        Elf64_Phdr* phdr = &ctx->phtab[i];
        if (phdr->p_type == PT_LOAD && phdr->p_flags & (PF_R | PF_W | PF_X)) {
            ctx->text_phdr = phdr;
        }
        if (phdr->p_type == PT_PHDR) {
            ctx->phdr = phdr;
        }
    }

    ctx->new_phdr = calloc(1,sizeof(Elf64_Phdr));
    ctx->new_phdr->p_type = PT_LOAD;
    ctx->new_phdr->p_flags = (PF_R |PF_X);
    ctx->new_phdr->p_align = ctx->text_phdr->p_align;

    return 0;
}

static void set_new_program_header(woodyCtx *ctx, size_t size, size_t sz_payload) {

    /* HAcemos que el nuevo phdr esté contenido en la nueva seccion load, si no, falla. */
    ctx->new_phdr->p_filesz = (sizeof(Elf64_Phdr) * (1 + ctx->elf_hdr->e_phnum)) + sizeof(sz_payload);
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

static void patch_phdr(woodyCtx *ctx) {

    size_t original_phtab_size = sizeof(Elf64_Phdr)*(ctx->elf_hdr->e_phnum);

    ctx->phdr->p_offset = ctx->new_phdr->p_offset; // Nuestra nueva seccion contiene al principio la phtab
    ctx->phdr->p_filesz = original_phtab_size;
    ctx->phdr->p_memsz = ctx->phdr->p_filesz;
    /* La vaddr hay que cambiarla para que tenga sentido con el nuevo offset. Sin esto, eplota. */
    ctx->phdr->p_vaddr = ctx->new_phdr->p_vaddr;

    assert(ctx->phdr->p_offset % ctx->phdr->p_align == ctx->phdr->p_vaddr % ctx->phdr->p_align);

    /* Modificamos el Elf header */
    ctx->elf_hdr->e_phnum += 1;
    ctx->elf_hdr->e_phoff = ctx->phdr->p_offset;
    ctx->elf_hdr->e_entry = ctx->new_phdr->p_vaddr + original_phtab_size + sizeof(Elf64_Phdr);
}


int do_woody(char* filename, int fd, void* map, size_t size) {

    Elf64_Ehdr *ehdr = map;          /* Elf Header */
    woodyCtx *ctx = &(woodyCtx){0};

    /* static global, used in every swap */
    end = ehdr->e_ident[EI_DATA];
    if (IS_NOT_ELF(ehdr)) {
        return 1;
    }

    initialize_context(ctx, map, size);

    char new_filename[100]={0};
    sprintf(new_filename, "%s_out", filename);
    int fd_new = open("woody_out", O_CREAT | O_RDWR, 00744);
    if (fd_new == -1) {
        printf("Cannot open file \n");
        return 1;
    }

    const char payload[]=
        "\xb8\x01\x00\x00\x00\xbf\x01\x00\x00\x00\x48\x8d"
        "\x35\x11\x00\x00\x00\xba\x0a\x00\x00\x00\x0f\x05"
        "\xb8\x3c\x00\x00\x00\x48\x31\xff\x0f\x05\x2e\x2e"
        "\x57\x4f\x4f\x44\x59\x2e\x2e\x0a";

    set_new_program_header(ctx, size, sizeof(payload));
    patch_phdr(ctx);

    /* Si el binario está stripped, no tenemos forma de saber el tamaño de .text. En teoría, muy en teoría,
     * se podría parsear PT_DYNAMIC para quitar los trozos de la PT_LOAD con PF_X|PF_R que se indican en los
     * DT_RELA, DT_FINI, DT_INIT, DT_PLTREL etc.
     * Es un curro que no voy a hacer, si me das un binario stripped, este método no funciona.
     */

    /* Buscamos la seccion que vamos a cifrar, la .text. Cifrar otras secciones del PT_LOAD pueden cargarse la carga dinámica.
     * Sobretodo: .plt.got y las .rela */
    Elf64_Shdr *shdr = map + ctx->elf_hdr->e_shoff;
    if ((char*)shdr - (char*)map > size) {
        fprintf(stderr, "Unable to retrieve .text section from program headers");
        return 1;
    }
    Elf64_Shdr *shstrtab = &shdr[ctx->elf_hdr->e_shstrndx];
    Elf64_Shdr *text_shdr = NULL;
    for (int i=0; i < ctx->elf_hdr->e_shnum; i++) {
        Elf64_Shdr *_shdr = &shdr[i];
        if (_shdr->sh_type == SHT_PROGBITS &&
            !strncmp(".text", map+shstrtab->sh_offset+_shdr->sh_name, strlen(".text")+1)) {
            text_shdr = _shdr;
            break;
        }
    }
    /* Aqui tenemos la .text section para poder cifrarla */

    printf("sh_offset=%lx, sh_addr=%lx, sh_size=%lx", text_shdr->sh_offset, text_shdr->sh_addr, text_shdr->sh_size);

    /* Escribimos el contenido del fichero*/
    write(fd_new, map, size);

    /* Creamos espacio dentro del archivo para lo que vamos a escribir */
    fallocate(fd_new, FALLOC_FL_ZERO_RANGE, size, ALIGNED_SIZE(ctx->new_phdr) - size);

    /* Copiamos la phtable actual al final del fichero (-1 porque ya está sumado el nuevo PT_LOAD)*/
    lseek(fd_new, ctx->phdr->p_offset, SEEK_SET);
    write(fd_new, ctx->phtab, sizeof(Elf64_Phdr)*(ctx->elf_hdr->e_phnum-1));

    /* Añadimos nuestro phdr */
    write(fd_new, ctx->new_phdr, sizeof(Elf64_Phdr));

    /* Escribimos el payload */
    lseek(fd_new, ctx->new_phdr->p_offset + sizeof(Elf64_Phdr)*ctx->elf_hdr->e_phnum, SEEK_SET);
    write(fd_new, payload, sizeof(payload));

    exit(0);
}

int woody_main(char* filename) {

    int fd = -1;
    struct stat st;
    int ret = 0;
    void* map = MAP_FAILED;

    if ((fd = open(filename, O_RDONLY | O_NONBLOCK)) == -1) {
        goto print_errno;
    }
    if (fstat(fd, &st) == -1) {
        goto print_errno;
    }
    if ((map = mmap(NULL, st.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0)) == MAP_FAILED) {
        goto print_errno;
    }
    if (ft_strncmp((const char *)map, ELFMAG, SELFMAG)) {
        goto print_file_format_not_recognized;
    }
    switch ((int)((unsigned char *)map)[EI_CLASS]) {
        case ELFCLASS64:
            if ((unsigned long)st.st_size < sizeof(Elf64_Ehdr)
                || do_woody(filename, fd, map, st.st_size) == -1)
                goto print_file_format_not_recognized;
            break;
        default:
            goto print_file_format_not_recognized;
    }
    goto cleanup;

print_file_format_not_recognized:
    fprintf(stderr, "ft_nm: %s: file format not recognized\n", filename);
    ret = 1;
print_errno:
    if (errno != 0) {
        ret = errno;
        fprintf(stderr, "%s: %s\n", "ft_nm: ", strerror(errno));
    }
cleanup:
    if (map != MAP_FAILED && munmap(map, st.st_size) == -1) {
        ret = errno;
        fprintf(stderr, "%s: %s\n", "ft_nm: ", strerror(errno));
    }
    if (fd != -1 && close(fd) == -1) {
        ret = errno;
        fprintf(stderr, "%s: %s\n", "ft_nm: ", strerror(errno));
    }
    return ret;
}

int main(int argc,char** argv) {

    char filename[4096] = {0};

    for (int i=1; i<argc; i++) {
        if (argv[i]) {
            memcpy(filename, argv[i], ft_strlen(argv[i]));
        }
        woody_main(filename);
    }
    return 0;
}


#ifdef __woodydebug
void debug_program_header(void* map, Elf64_Half size, Elf64_Phdr* phdr) {

    (void*)map;
    (void)size;
    printf("===> Program Header <=====");
    printf("TYPE=");
    switch(phdr->p_type) {
        case PT_NULL: printf("PT_NULL"); break;
        case PT_LOAD: printf("PT_LOAD"); break;
        case PT_DYNAMIC: printf("PT_DYNAMIC"); break;
        case PT_INTERP: printf("PT_INTERP"); break;
        case PT_NOTE: printf("PT_NOTE"); break;
        case PT_SHLIB: printf("PT_SHLIB"); break;
        case PT_PHDR: printf("PT_PHDR"); break;
        case PT_TLS: printf("PT_TLS"); break;
        case PT_NUM: printf("PT_NUM"); break;
        case PT_LOOS: printf("PT_LOOS"); break;
        case PT_GNU_EH_FRAME: printf("PT_GNU_EH_FRAME"); break;
        case PT_GNU_STACK: printf("PT_GNU_STACK"); break;
        case PT_GNU_RELRO: printf("PT_GNU_RELRO"); break;
        case PT_GNU_PROPERTY: printf("PT_GNU_PROPERTY"); break;
        case PT_GNU_SFRAME: printf("PT_GNU_SFRAME"); break;
        case PT_LOSUNW: printf("PT_LOSUNW|PT_SUNWBSS"); break;
        case PT_SUNWSTACK: printf("PT_SUNWSTACK"); break;
        case PT_HISUNW: printf("PT_HISUNW|PT_HIOS"); break;
        case PT_LOPROC: printf("PT_LOPROC"); break;
        case PT_HIPROC: printf("PT_HIPROC"); break;
        default: printf("????: %x", phdr->p_type);
    }
    printf("\n");
    printf("FLAGS={");
    if (phdr->p_flags & PF_X) printf(" PF_X");
    if (phdr->p_flags & PF_W) printf(" PF_W");
    if (phdr->p_flags & PF_R) printf(" PF_R");
    if (phdr->p_flags & PF_MASKPROC) printf(" PF_MASKPROC");
    if (phdr->p_flags & PF_MASKOS) printf(" PF_MASKOS");
    printf(" }\n");
    printf("phdr->p_align=%016lx\n", phdr->p_align);
    printf("phdr->p_filesz=%016lx\n", phdr->p_filesz);
    printf("phdr->p_memsz=%016lx\n", phdr->p_memsz);
    printf("phdr->p_offset=%016lx\n", phdr->p_offset);
    printf("phdr->p_paddr=%016lx\n", phdr->p_paddr);
    printf("phdr->p_vaddr=%016lx\n", phdr->p_vaddr);
    printf("------------------------------------------------------------\n");
}
#endif
