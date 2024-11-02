#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/mman.h>
#include <errno.h>

//const char payload[] = "\x48\x89\xe7\xc6\x07\x57\xc6\x47\x01\x4f\xc6\x47\x02\x4f\xc6\x47\x03\x44\xc6\x47\x04\x59\xc6\x47\x05\x0a\x48\x89\xfe\xb8\x01\x00\x00\x00\xbf\x01\x00\x00\x00\xba\x06\x00\x00\x00\x0f\x05\xb8\x3c\x00\x00\x00\x48\x31\xff\x0f\x05";
const char payload[] = "\x48\x89\xe7\xc6\x07\x57\xc6\x47\x01\x4f\xc6\x47\x02\x4f\xc6\x47\x03\x44\xc6\x47\x04\x59\xc6\x47\x05\x0a\x48\x89\xfe\xb8\x01\x00\x00\x00\xbf\x01\x00\x00\x00\xba\x06\x00\x00\x00\x0f\x05\xb8\x3c\x00\x00\x00\x48\x31\xff\x0f\x05";


int main() {
	printf("main @ %p\n", &main);
	printf("payload @ %p\n", &payload);

	printf("Making payload executable ...\n");
	/* Esto no funciona porque da EINVAL. Ver man de mprotect y buscar
	int ret = mprotect(
		(void*)payload,
		sizeof(payload),
		PROT_READ | PROT_EXEC
	);
	*/
	// Las paginas son normalmente multiples de 4KiB. Queremos, por tanto, que en la hex rep
	// de la address que le pasamos aparezca 0x000 al final
	size_t region = (size_t)payload;
	region &= (~0xfff);
	int ret = mprotect(
		(void*)region,
		0x1000,
		PROT_READ | PROT_EXEC
	);
	if (ret != 0) {
		printf("mprotect failed: error %d\n", errno);
		return 1;
	}
	void (*f)(void) = (void*)payload;
	f();
	return 0;	
}
