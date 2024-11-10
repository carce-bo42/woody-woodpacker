#include "libft.h"

char	*ft_strdup(const char *src)
{
	char	*out = (char *) malloc(sizeof (*src) * (ft_strlen(src) + 1));

	if (!out)
		return (NULL);
	while (*src) {
		*out++ = *src++;
	}
	*out = 0;
	return (out);
}
