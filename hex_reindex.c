#include <stdio.h>


int main()
{
	int arry[5] = {3, 0, 5, 8, 6};
	int index[5] = {0};

	int i, j;
	for(i = 0; i < 5; i++)
	{
		for(j = 0; j < 5; j++)
			index[i] = arry[i]<arry[j]?index[i]:index[i]+1;
	}

	for(i = 0; i < 5; i++)
		printf("%d\t", index[i]);

	return 0;
}

