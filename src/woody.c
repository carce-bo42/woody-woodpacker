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
#include <stddef.h>

void debug_program_header(void* map, Elf64_Half size, Elf64_Phdr* phdr);

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

/* See https://refspecs.linuxfoundation.org/elf/gabi4+/ch4.eheader.html#elfid */
static size_t get_ehdr_e_shnum(void* map, Elf64_Ehdr* ehdr) {
    if (ehdr->e_shnum >= SHN_LORESERVE) {
        return swap(((Elf64_Shdr *)(map + swap(ehdr->e_shoff)))->sh_size);
    }
    return swap(ehdr->e_shnum);
}

void prepare_new_phdr(int fd_new, Elf64_Phdr *new_phdr, Elf64_Phdr *last,
                      Elf64_Ehdr *ehdr, size_t size, Elf64_Half phtable_size)
{
    new_phdr->p_flags += (PF_X | PF_W | PF_R);

    // TODO seguramente, por culpa del align, esto tenga que tener padding respecto al final del
    // archivo y por tanto, lo que dice tomás es cierto
    new_phdr->p_align = 0x1000;
    new_phdr->p_type = PT_LOAD;

    new_phdr->p_offset = (size + 0xfff) & (~0xfff);

    /* Alineamos nuestro vaddr con el vaddr mayor que hayamos encontrado. La operacion bitwise
     * es para que tenga 000 al final, alineado con las paginas de 4K.
     */
    new_phdr->p_vaddr = ((last->p_vaddr + last->p_memsz + new_phdr->p_align)) & (~(new_phdr->p_align-1));
    new_phdr->p_paddr = last->p_vaddr;
    /* Esto ya cuando sepa el payload amigo */
    new_phdr->p_memsz = 0x5000;
    new_phdr->p_filesz = 0x5000;

    /* Copiamos el nuevo phdr al final de la phtable (previamente hemos copiado el resto) */
    lseek(fd_new, 0, SEEK_END);
    write(fd_new, new_phdr, sizeof(Elf64_Phdr));
}

uint64_t get_multiple_of_alignments_needed(Elf64_Off alignment, uint64_t size) {
    return size/alignment +1;
}


int do_woody(char* filename, int fd, void* map, size_t size) {

    Elf64_Ehdr *ehdr = map;          /* Elf Header */
    Elf64_Half phnum = -1;

    /* static global, used in every swap */
    end = ehdr->e_ident[EI_DATA];

    if (IS_NOT_ELF(ehdr)) {
        return -1;
    }

    Elf64_Addr entrypoint = ehdr->e_entry;
    Elf64_Phdr *phtab = map + ehdr->e_phoff;    /* Program Header Table */

    phnum = ehdr->e_phnum;

    /* phnum * swap(ehdr->e_phentsize) = bytes de la Program Header Table */

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

    // Modificamos todas las secciones que estén después de .text para dar espacio a ensanchar la .text.
    // El tamaño que ensanchamos concuerda con un múltiple de la alineación de la .text, para evitar
    // preocuparse del alineamiento en el resto de secciones que movamos: la .text section tiene el
    // alineamiento más grande, suele estar en múltiples de páginas de 4Kb=4096b o 0x1000b.
    Elf64_Off text_offset = text_phdr->p_offset;
    Elf64_Xword orig_text_aligned_size = (text_phdr->p_filesz+ text_phdr->p_align - 1) & ~(text_phdr->p_align - 1);

    // Pondremos el payload al final de la última página donde estuviese la .text original.
    Elf64_Off payload_size = 4242;
    Elf64_Off new_text_unaligned_size = orig_text_aligned_size + payload_size;

    // Para saber donde acabará la .text section nueva y por tanto dónde empiezan las otras, tenemos que saber cuantas páginas más tenemos
    // que añadir para que quepa el payload:
    Elf64_Off new_aligned_size = (new_text_unaligned_size + text_phdr->p_align - 1) & ~(text_phdr->p_align -1);

    // El delta que habremos movido el final de la seccion .text es:
    Elf64_Off shift = new_aligned_size - orig_text_aligned_size;

    // Reubicamos todas las secciones que no estaban dentro de .text originalmente.
    // Movemos primero las secciones más altas en memoria para que no se sobrescriban los datos de las secciones posteriores.

    // Primero recojemos los phdr que habrá que shiftear
    Elf64_Off orig_text_end = text_phdr->p_offset + orig_text_aligned_size;
    Elf64_Phdr *phdr_set[100] = {0};
    int idx = 0;
    Elf64_Off max_position = 0;
    for (Elf64_Half i = 0; i < phnum; i++) {
        Elf64_Phdr* phdr = &phtab[i];
        if (phdr->p_offset > orig_text_end) {
            phdr_set[idx++] = phdr;
            /* Buscamos la última posición alineada que va a necesitar el ficherín */
            Elf64_Off aligned_size = (phdr->p_filesz + phdr->p_align - 1) & ~(phdr->p_align - 1);
            if (phdr->p_offset + aligned_size > max_position) {
                max_position = phdr->p_offset + aligned_size;
            }
        }
    }

    // Ensanchamos el tamaño del fichero de salida si vemos que nos faltará espacio incluso sobreescribiendo las secciones.
    if (max_position + shift > size) {
        lseek(fd_new, 0, SEEK_END);
        write(fd_new, (char[0x1000]){0,}, max_position + shift - size);
    }

    qsort(phdr_set, (size_t)idx, sizeof(Elf64_Phdr *), _compare_elf_phdr);

    for (Elf64_Half i = 0; i < idx; i++) {
        Elf64_Phdr* phdr = phdr_set[i];

        // Copiamos el contenido de la seccion
        lseek(fd_new, phdr->p_offset + shift, SEEK_SET);
        write(fd_new, map + phdr->p_offset, phdr->p_filesz);

        // Cambiamos el offset en la phtable
        lseek(fd_new, ((void*)phdr - map) + offsetof(Elf64_Phdr, p_offset), SEEK_SET);
        write(fd_new, &(Elf64_Off){phdr->p_offset + shift}, sizeof(Elf64_Off));
    }

    /***************************************************************************** */
    // basura antigua
    exit(0);

    Elf64_Phdr *last_phdr = NULL;
    Elf64_Off max_poff_plus_size = 0;
    Elf64_Half phtable_size = phnum * ehdr->e_phentsize;

    // Siguiente chunk de 0x1000 es donde nosotros queremos apuntar
    int padding = ((size + 0xfff) & (~0xfff)) - size;
    printf("padding: %i\n", padding);
    lseek(fd_new, 0, SEEK_END);
    write(fd_new, (char[0x1000]){0,}, padding);

    Elf64_Off phentsize = 0;
    for (Elf64_Half i = 0; i < phnum; i++) {
        Elf64_Phdr* phdr = (void*)phtab + i*phentsize;
        Elf64_Word sh_type = phdr->p_type;
        //debug_program_header(map, size, phdr);
        if (sh_type == PT_LOAD && phdr->p_flags & (PF_W |PF_X)) {


        }
        if (phdr->p_offset + phdr->p_filesz > max_poff_plus_size) {
            max_poff_plus_size = phdr->p_offset + phdr->p_filesz;
        }
        /* Find last program header. this is not even necessary. */
        if (sh_type == PT_LOAD) {
            if (last_phdr == NULL) {
                last_phdr = phdr;
            } else {
                if (last_phdr->p_vaddr < phdr->p_vaddr) {
                    last_phdr = phdr;
                }
            }
        }
        /* Vamos copiando los phdr al final del nuevo elf */
        lseek(fd_new, 0, SEEK_END);
        write(fd_new, phdr, phentsize);
    }

    exit(0);

    printf("max_poff_plus_size = %x\n", max_poff_plus_size);
    printf("size = %x\n", size);

    /* El tema */
    // char payload[] = "\xbf\x01\x00\x00\x00\x48\x8d\x35\x14\x00\x00\x00\xba\x0a\x00\x00"
    //                  "\x00\x0f\x05\x49\xba\x42\x42\x42\x42\x42\x42\x42\x42\x41\xff\xe2"
    //                  "\x2e\x2e\x57\x4f\x4f\x44\x59\x2e\x2e\x0a";

    // char payload[] = "\xbf\x01\x00\x00\x00\x48\x8d\x35\x11\x00\x00\x00\xba\x0a\x00\x00\x00\x0f\x05\xb8\x3c\x00\x00\x00\x48\x31\xff\x0f\x05\x2e\x2e\x57\x4f\x4f\x44\x59\x2e\x2e\x0a";
    // memcpy(&payload[20], (void*)ehdr->e_entry, sizeof(ehdr->e_entry));

    /* metemos el nuevo phdr que apunta al codigo infectado */
    Elf64_Phdr *new_phdr = malloc(sizeof(Elf64_Phdr));
    prepare_new_phdr(fd_new, new_phdr, last_phdr, ehdr, size, phtable_size);

    /* change entrypoint*/
    printf("old_entrypoint = %lu\n", ehdr->e_entry);
    Elf64_Addr new_entrypoint = new_phdr->p_vaddr;
    printf("new_entrypoint = %lu\n", new_entrypoint);
    lseek(fd_new, offsetof(Elf64_Ehdr, e_entry), SEEK_SET);
    // write(fd_new, &new_entrypoint, sizeof(Elf64_Addr));

    /* change phnum */
    Elf64_Half new_phnum = phnum + 1;
    printf("new_phnum = %lu\n", new_phnum);
    lseek(fd_new, offsetof(Elf64_Ehdr, e_phnum), SEEK_SET);
    write(fd_new, &new_phnum, sizeof(Elf64_Half));

    /* change offset of phtable in ehdr */
    printf("new_phoff = %lu\n", size);
    Elf64_Off new_phoff = size + padding;
    lseek(fd_new, offsetof(Elf64_Ehdr, e_phoff), SEEK_SET);
    write(fd_new, &new_phoff, sizeof(Elf64_Off));

    /* Change memsz, filesz, vaddr of the first phdr */

    /* Ahora el filesz de los phdr será un pelin mas grande */
    Elf64_Off new_filesz = phtable_size + ehdr->e_phentsize;
    lseek(fd_new, size + padding + offsetof(Elf64_Phdr, p_filesz), SEEK_SET);
    write(fd_new, &new_filesz, sizeof(Elf64_Xword));

    lseek(fd_new, size + padding + offsetof(Elf64_Phdr, p_memsz), SEEK_SET);
    write(fd_new, &new_filesz, sizeof(Elf64_Xword));

    /* Y la vaddr la pongo donde puse el inicio del nuevo PT_LOAD. Así lo
     * engloba todo y no tengo errores de que PHDR is not covered by LOAD section
     */
    Elf64_Addr new_vaddr = new_phdr->p_vaddr;
    lseek(fd_new, size + padding + offsetof(Elf64_Phdr, p_vaddr), SEEK_SET);
    write(fd_new, &new_vaddr, sizeof(Elf64_Addr));

    lseek(fd_new, size + padding + offsetof(Elf64_Phdr, p_paddr), SEEK_SET);
    write(fd_new, &new_vaddr, sizeof(Elf64_Addr));

    /* Escribimos el nuevo offset en el phdr. */
    lseek(fd_new, size + padding + offsetof(Elf64_Phdr, p_offset), SEEK_SET);
    write(fd_new, &new_phoff, sizeof(Elf64_Off));

    // lseek(fd_new, new_phdr->p_offset + phtable_size + ehdr->e_phentsize, SEEK_SET);
    // write(fd_new, payload, sizeof(payload));

    close(fd_new);
    free(new_phdr);
    printf("END\n");


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

    // Tenemos que poder enlazar al .text cuando estemos en ejecucion. Pero el ASLR
    // hace que haya un offset en runtime, asi que tiene que ir en el asm.

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
