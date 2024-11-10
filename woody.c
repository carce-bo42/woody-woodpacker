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

/* Endianness of the binary */
static int end = 0;

#define swap(p) (end == ELFDATA2LSB ? p : \
                    sizeof(p) == 8 ? __builtin_bswap64(p) : \
                    sizeof(p) == 4 ? __builtin_bswap32(p) : \
                                     __builtin_bswap16(p))


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
    Elf64_Shdr *shstrtab = NULL;     /* Section Header String Table */
    Elf64_Shdr *symtab = NULL;       /* Symbol Table */
    Elf64_Shdr *strtab = NULL;       /* Symbol Table's String Table */
    Elf64_Shdr *symtab_shndx = NULL; /* Symbol Table Extended Section indexes */
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

    Elf64_Off e_phoff = swap(ehdr->e_shoff);
    Elf64_Phdr *phtab = map + e_phoff;                /* Program Header Table */
    Elf64_Half phentsize = swap(ehdr->e_phentsize); /* Program Header Table entry size */

    phnum = swap(ehdr->e_phnum);
    for (size_t i = 0; i < phnum; i++) {
        Elf64_Phdr* phdr = (void*)phtab + i*phentsize;
        Elf64_Word sh_type = swap(phdr->p_type);      /* Section type */
        /* SHT_SYMTAB sólo puede haber una, la del linker es SHT_DYNSYM */
        if (sh_type == PT_LOAD) {
            printf("un PT_LOAD");
        }
        /* Hay casos turbios en los que esto es necesario */
        if (sh_type == SHT_SYMTAB_SHNDX) {
            symtab_shndx = section;
        }
    }

}


void woody_main(char* filename) {

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

    char filename[4096] = 0;

    for (int i=1; i<argc; i++) {
        if (argv[i]) {
            memcpy(filename, argv[i], ft_strlen(argv[i]));
        }
        woody_main(filename);
    }
    return 0;
}
