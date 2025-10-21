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
    Elf64_Phdr **in_phdrs;
    Elf64_Phdr **out_phdrs;
    Elf64_Ehdr *elf_hdr;
    Elf64_Phdr *in_text_phdr;
    Elf64_Phdr *out_text_phdr;
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

// Modificamos todas las secciones que estén después de .text para dar espacio a ensanchar la .text.
// El tamaño que ensanchamos concuerda con un múltiple de la alineación de la .text, para evitar
// preocuparse del alineamiento en el resto de secciones que movamos: la .text section tiene el
// alineamiento más grande, suele estar en múltiples de páginas de 4Kb=4096b o 0x1000b.
int expand_text_section_to_fit_payload(void *map, size_t size, int fd, Elf64_Phdr *text_phdr, size_t payload_size) {

    Elf64_Phdr *phtab = map + ((Elf64_Ehdr*)map)->e_phoff;
    Elf64_Half phnum = ((Elf64_Ehdr*)map)->e_phnum;

    // Buscamos las secciones que tienen ubicadas después del final del chunk apuntado por
    // el program header de la .text section: serán las que tengamos que mover.
    Elf64_Phdr *phdr_set[100] = {0};
    int idx = 0;
    Elf64_Off max_position = 0;
    for (Elf64_Half i = 0; i < phnum; i++) {
        Elf64_Phdr* phdr = &phtab[i];

        if (phdr->p_offset >= text_phdr->p_offset + ALIGNED_SIZE(text_phdr)) {
            phdr_set[idx++] = phdr;
            /* Buscamos la última posición alineada que va a necesitar el ficherín */
            Elf64_Off aligned_size = ALIGNED_SIZE(phdr);
            if (phdr->p_offset + aligned_size > max_position) {
                max_position = phdr->p_offset + aligned_size;
            }
        }
    }

    // Ensanchamos el tamaño del fichero de salida si vemos que nos faltará espacio incluso sobreescribiendo las secciones.
    Elf64_Off shift = ALIGN(ALIGNED_SIZE(text_phdr) + payload_size, text_phdr->p_align) - ALIGNED_SIZE(text_phdr);
    if (max_position + shift > size) {
        fallocate(fd, FALLOC_FL_ZERO_RANGE, size, shift);
    }

    qsort(phdr_set, (size_t)idx, sizeof(Elf64_Phdr *), _compare_elf_phdr);

    for (Elf64_Half i = 0; i < idx; i++) {
        Elf64_Phdr* phdr = phdr_set[i];

        // Copiamos el contenido de la seccion
        lseek(fd, phdr->p_offset + shift, SEEK_SET);
        write(fd, map + phdr->p_offset, phdr->p_filesz);

        // Cambiamos el offset en la phtable
        lseek(fd, ((void*)phdr - map) + offsetof(Elf64_Phdr, p_offset), SEEK_SET);
        write(fd, &(Elf64_Off){phdr->p_offset + shift}, sizeof(Elf64_Off));

    }

    return 0;
}


int do_woody(char* filename, int fd, void* map, size_t size) {

    Elf64_Ehdr *ehdr = map;          /* Elf Header */
    Elf64_Half phnum = -1;

    /* static global, used in every swap */
    end = ehdr->e_ident[EI_DATA];

    if (IS_NOT_ELF(ehdr)) {
        return -1;
    }

    Elf64_Phdr *phtab = map + ehdr->e_phoff;    /* Program Header Table */
    phnum = ehdr->e_phnum;

    char new_filename[100]={0};
    sprintf(new_filename, "%s_out", filename);
    int fd_new = open(new_filename, O_CREAT | O_RDWR, 00744);
    if (fd_new == -1) {
        printf("Cannot open file \n");
    }

    // copiamos el fichero entero inicialmente
    // TODO quizás separar en escrituras de tamaños de pagina para que esto
    // no se suicide si el binario es gigantesco
    write(fd_new, map, size);
    Elf64_Phdr *text_phdr;

    // Find the .text section
    for (Elf64_Half i = 0; i < phnum; i++) {
        Elf64_Phdr* phdr = &phtab[i];
        if (phdr->p_type == PT_LOAD && phdr->p_flags & (PF_W |PF_X)) {
            text_phdr = phdr;
            break;
        }
    }

    /*
     * Una vez un elf está construido, es completamente irrelevante la información de los section headers.
     * Prueba de ello es lo que hace el binario strip. Aun así, sepamos que el binario dejemos estará
     * claramente mal a ojos de herramientas de analisis estático, porque no vamos a borrar esas secciones,
     * vamos a sobreescribirlas parcialmente.
     */

    const char payload[]="\xb8\x01\x00\x00\x00\xbf\x01\x00\x00\x00\x48\x8d\x35\x11\x00\x00\x00\xba\x0a\x00\x00\x00\x0f\x05\xb8\x3c\x00\x00\x00\x48\x31\xff\x0f\x05\x2e\x2e\x57\x4f\x4f\x44\x59\x2e\x2e\x0a";
    if (sizeof(payload) < //expand_text_section_to_fit_payload(map, size, fd_new, text_phdr, sizeof(payload));

    // Inyectamos el código, y cambiamos el entrypoint
    lseek(fd_new, text_phdr->p_offset + text_phdr->p_filesz + 1, SEEK_SET);
    write(fd_new, payload, sizeof(payload));

    Elf64_Addr injection_offset = text_phdr->p_vaddr + text_phdr->p_memsz + 1 ;
    lseek(fd_new, offsetof(Elf64_Ehdr, e_entry), SEEK_SET);
    write(fd_new, &injection_offset, sizeof(Elf64_Addr));

    // Modificamos finalmente el filesz y el memsz de la .text section:
    Elf64_Xword new_size = ALIGN(text_phdr->p_memsz + sizeof(payload), text_phdr->p_align);

    // lseek(fd_new, (void*)&text_phdr->p_filesz - map, SEEK_SET);
    // write(fd_new, &new_size, sizeof(Elf64_Xword));

    // lseek(fd_new, (void*)&text_phdr->p_memsz - map, SEEK_SET);
    // write(fd_new, &new_size, sizeof(Elf64_Xword));

    // Escribimos nuestro payload
    exit(0);


/*
typedef struct {
    unsigned char e_ident[16]; // 16 bytes
    uint16_t e_type;           // 2 bytes
    uint16_t e_machine;        // 2 bytes
    uint32_t e_version;        // 4 bytes
    uint64_t e_entry;          // 8 bytes
    uint64_t e_phoff;          // 8 bytes
    uint64_t e_shoff;          // 8 bytes
    uint32_t e_flags;          // 4 bytes
    uint16_t e_ehsize;         // 2 bytes
    uint16_t e_phentsize;      // 2 bytes
    uint16_t e_phnum;          // 2 bytes
    uint16_t e_shentsize;      // 2 bytes
    uint16_t e_shnum;          // 2 bytes
    uint16_t e_shstrndx;       // 2 bytes
} Elf64_Ehdr;
*/

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
    if ((map = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0)) == MAP_FAILED) {
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
