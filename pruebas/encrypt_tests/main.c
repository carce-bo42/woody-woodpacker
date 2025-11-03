#include <stddef.h>

void encrypt(const char key[48], const char * pt, size_t pt_sz, char * restrict ct, size_t ct_sz) {
    for (int i=0; i < pt_sz; i++) {
        *ct = *pt ^ key[i%48];
    }
}

int main() {
	const char key[48] = "01234567890123456789012345678901234567890123456";
	const char pt[32] = "oh hello there i am a plaintext";
	char ct[32] = {0};
	
	encrypt(key, pt, sizeof(pt), ct, sizeof(ct));
	return 0;
}
