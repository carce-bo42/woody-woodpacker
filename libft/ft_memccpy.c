#include "libft.h"

void	*ft_memccpy(void *dst, const void *src, int c, size_t n)
{
	while (n-- > 0)
	{
		*(unsigned char *)dst = *(const unsigned char *)src;
		if (*(unsigned char *)src == (unsigned char)c)
			return ((void *)++dst);
		dst++;
		src++;
	}
	return (NULL);
}
