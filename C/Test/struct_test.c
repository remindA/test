#include <stdio.h>
#include <string.h>
#include <stdlib.h>

struct list_head
{
    struct list_head *prev, *next;
};

typedef struct
{
    struct list_head list;
    unsigned long a;
    unsigned long b;
    unsigned long c;
    char *rplstr;
}s_meminfo;

struct list_head list;

s_meminfo info;
int main()
{
    /*
       s_meminfo *meminfo = (s_meminfo*)malloc(sizeof(s_meminfo));
       unsigned long *mem = (unsigned long*)meminfo;
       int i = 0;
       for(i = 0; i < 3; i++)
       {
     *(mem + i) = i+1;
     }
     for(i = 0; i < 3; i++)
     printf("mem.number%d=%lu\n", i+1, *(mem + i));

     printf("\n");
     printf("%ld\n", meminfo->a);
     printf("%ld\n", meminfo->b);
     printf("%ld\n", meminfo->c);

     int x = 3;
     printf("print:x++=%d\n", x++);
     free(meminfo);
     */
    printf("%ld\n", info.a);
    printf("%ld\n", info.b);
    printf("%ld\n", info.c);
    printf("info.rplstr=%p\n", info.rplstr);
    printf("info.list.prev=%p\n", info.list.prev);
    printf("info.list.next=%p\n", info.list.next);

    memset(&list, 0, sizeof(list));
    printf("list.prev=%p\n", list.prev);
    printf("list.next=%p\n", list.next);
    return 0;
}
