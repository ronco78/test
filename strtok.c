#include <stdio.h>

static char *olds;

size_t strlen( const char *str )
{
	size_t len = 0;

	while(str[len])
		len++;

	return len;
}

char *strpbrk(const char *s, const char *accept)
{
	while (*s != '\0') {
		const char *a = accept;
		while (*a != '\0')
			if (*++a == *s)
				return (char *) s;
		++s;
	}

	return NULL;
}

char *strtok(char *s, const char *delim)
{
	char *token;

	if (s == NULL)
		s = olds;

	token = s;
	s = strpbrk(token, delim);
	if (s == NULL)
		olds = token + strlen(token);
	else {
		*s = '\0';
		olds = s + 1;
	}

	return token;
}

int main(int argc, char **argv)
{
	char *token;

	token = strtok(argv[0], argv[1]);
	while (token) {
		printf("%s\n", token);
		token = strtok(NULL, argv[1]);
	}
}

