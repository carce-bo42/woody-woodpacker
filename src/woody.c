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
#include <fcntl.h>
#include <sys/mman.h>
#include <string.h>

void debug_program_header(void* map, size_t size, Elf64_Phdr* phdr);

/* Endianness of the binary */
static int end = 0;

#define swap(p) (end == ELFDATA2LSB ? p : \
                    sizeof(p) == 8 ? __builtin_bswap64(p) : \
                    sizeof(p) == 4 ? __builtin_bswap32(p) : \
                                     __builtin_bswap16(p))

/* See https://refspecs.linuxfoundation.org/elf/gabi4+/ch4.eheader.html#elfid */
static size_t get_ehdr_e_shnum(void* map, Elf64_Ehdr* ehdr) {
    if (ehdr->e_shnum >= SHN_LORESERVE) {
        return swap(((Elf64_Shdr *)(map + swap(ehdr->e_shoff)))->sh_size);
    }
    return swap(ehdr->e_shnum);
}

/*
 * Calcula cuanto mide el fichero elf buscando cual es el offset + tamaño
 * más grande que hay. De esta forma el orden dentro del fichero nos da igual.
 * See https://refspecs.linuxfoundation.org/elf/gabi4+/ch4.intro.html
 */
static size_t get_elf_size(void *map, Elf64_Ehdr *ehdr, size_t actual_size) {

    size_t total = 0;
    Elf64_Off phoff = swap(ehdr->e_phoff); /* Program Header Offset */
    Elf64_Off shoff = swap(ehdr->e_shoff); /* Section Header Offset */
    Elf64_Half shentsize = swap(ehdr->e_shentsize);
    Elf64_Half phentsize = swap(ehdr->e_phentsize);
    size_t shnum = get_ehdr_e_shnum(map, ehdr);
    Elf64_Half phnum = swap(ehdr->e_phnum);

    /* Most programs should be ok with this block */
    if (phoff < shoff) {
        total = shoff + shnum * shentsize;
    } else {
        total =  phoff + phnum * phentsize;
    }
    /* BUT this is not forbidden in the standard */
    for (size_t i = 0; i < phnum; i++) {
        if (phoff + i * phentsize > actual_size) {
            return -1;
        }
        Elf64_Phdr *phent = map + phoff + i * phentsize;
        Elf64_Off p_offset = swap(phent->p_offset);
        Elf64_Xword p_filesz = swap(phent->p_filesz);
        if (p_offset + p_filesz > total) {
            total = p_offset + p_filesz;
        }
    }
    for (size_t i = 0; i < shnum; i++) {
        if (shoff + i * shentsize > actual_size) {
            return -1;
        }
        Elf64_Shdr *shent = map + shoff + i * shentsize;
        Elf64_Off sh_offset = swap(shent->sh_offset);
        Elf64_Xword sh_size = swap(shent->sh_size);
        if (sh_offset + sh_size > total) {
            /* "A section of type SHT_NOBITS may have a non-zero size,
             * but it occupies no space in the file." */
            if (swap(shent->sh_type) != SHT_NOBITS ) {
                total = sh_offset + sh_size;
            }
        }
    }
    return total;
}

int do_woody(char* filename, void* map, size_t size) {

    Elf64_Ehdr *ehdr = map;          /* Elf Header */
    size_t phnum = -1;

    /* static global, used in every swap */
    end = ehdr->e_ident[EI_DATA];

    if ((ehdr->e_ident[EI_DATA] != ELFDATA2LSB
            && ehdr->e_ident[EI_DATA] != ELFDATA2MSB)
        || ehdr->e_ident[EI_VERSION] != EV_CURRENT
        || swap(ehdr->e_ehsize) != sizeof(Elf64_Ehdr)
        || swap(ehdr->e_shentsize) != sizeof(Elf64_Shdr)) {
        return -1;
    }

    Elf64_Addr entrypoint = ehdr->e_entry;
    Elf64_Phdr *phtab = map + swap(ehdr->e_phoff);    /* Program Header Table */
    Elf64_Half phentsize = swap(ehdr->e_phentsize);  /* Program Header Table entry size */

    phnum = swap(ehdr->e_phnum);
    Elf64_Phdr *last_phdr = NULL;
    for (size_t i = 0; i < phnum; i++) {
        Elf64_Phdr* phdr = (void*)phtab + i*phentsize;
        Elf64_Word sh_type = swap(phdr->p_type);
        debug_program_header(map, size, phdr);
        if (sh_type == PT_LOAD) {
            if (last_phdr == NULL) {
                last_phdr = phdr;
            } else {
                if (last_phdr->p_vaddr < phdr->p_vaddr) {
                    last_phdr = phdr;
                }
            }
        }
    }

    /* Hay que añadir un phdr al final, y luego el segmento justo despues del phdr.
     * Es sospechoso ? Que flipas. Pero y lo guapo que esta q.*/
    Elf64_Phdr *tuned_phdr = malloc(sizeof(Elf64_Phdr*));
    tuned_phdr->p_offset = size;
    tuned_phdr->p_flags += (PF_X | PF_R);
    tuned_phdr->p_align += 0x1000;
    // 0xfff = 0x1000 - 1
    // No me fio de esto, podría haber padding pero temas
    tuned_phdr->p_offset += size + sizeof(Elf64_Phdr);
    tuned_phdr->p_vaddr = ((last_phdr->p_vaddr + last_phdr->p_memsz+tuned_phdr->p_align) & (~0xfff));
    tuned_phdr->p_paddr = tuned_phdr->p_paddr;

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
                || do_woody(filename, map, st.st_size) == -1)
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


void debug_program_header(void* map, size_t size, Elf64_Phdr* phdr) {

    (void*)map;
    (void*)size;
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
