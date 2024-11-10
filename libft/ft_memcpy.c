#include "libft.h"

void	*ft_memcpy(void *dst, const void *src, size_t n)
{
	while (n-- > 0)
		*((unsigned char *)dst++) = *((unsigned char *)src++);
	return (dst);
}
