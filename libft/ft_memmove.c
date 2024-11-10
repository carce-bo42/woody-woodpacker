#include "libft.h"

void	*ft_memmove(void *dst, const void *src, size_t len)
{
	if (!dst && !src)
		return (NULL);
	if (dst > src)
		while (len-- > 0)
			*((unsigned char *)dst + len) = *((const unsigned char *)src + len);
	else
		while (len-- > 0)
			*(unsigned char *)dst++ = *(const unsigned char *)src++;
	return (dst);
}
