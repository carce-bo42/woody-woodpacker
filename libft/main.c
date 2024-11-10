#include <stdio.h>
#include <stdlib.h>
#include "libft.h"

int main() {
	//int lol = -123456789;
	int lol = 0;
	char *buf = ft_itoa(lol);

	printf("%s\n", buf);
	return 0;
}
