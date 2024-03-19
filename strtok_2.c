#include <stdio.h>

static char *olds;

size_t my_strlen( const char *str )
{
	size_t len;

	while(str[len])
		len++;

	return len;
}

char *my_strpbrk(const char *s, const char *accept)
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

char *my_strtok(char *s, const char *delim)
{
	char *token;

	if (s == NULL)
		s = olds;

	token = s;
	s = my_strpbrk(token, delim);
	if (s == NULL)
		olds = token + my_strlen(token);
	else {
		*s = '\0';
		olds = s + 1;
	}

	return token;
}

int main(int argc, char **argv)
{
	char *token;

	token = my_strtok(argv[0], argv[1]);
	while (token) {
		printf("%s\n", token);
		token = my_strtok(NULL, argv[1]);
	}
}

