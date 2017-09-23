#include <stdio.h>
#include <limits.h>
#include <stdlib.h>

int main()
{
	char path_absolute[128] = {0};
	printf("%s\n", realpath("./", path_absolute) );
	printf("%s\n", realpath("../", path_absolute) );



	return 0;
}
