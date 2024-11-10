#include "libft.h"

static char *reverse_nbr_string(char* buf) {

	size_t len = ft_strlen(buf);
	char *ret = malloc(len + 1);

	if (!ret) {
		return NULL;
	}
	ret[len] = 0;
	if (*buf == '-') {
		*ret = *buf++;
	}
	while (*buf) {
		ret[len-- - 1] = *buf++;
	}
	return ret;
}

// If I save the offset, I can put the final zero at the end.
static int do_itoa(int n, char *buf, int offset) {

	if (n < 10) {
		n = n + '0';
		buf[offset] = (char)n;
	} else {
		do_itoa((n % 10), buf, offset);
		offset = do_itoa((n / 10), buf, offset + 1);
	}
	return offset;
}

char	*ft_itoa(int n)
{
	char buf[12];
	int offset = 0;

	if (n == -2147483648)
		ft_strdup("-2147483648");
	if (n < 0) {
		n = n * (-1);
		buf[offset++] = '-';
	}
	offset = do_itoa(n, buf, offset);
	buf[offset + 1] = '\0';
	return reverse_nbr_string(buf);
}
