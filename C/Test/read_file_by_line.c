#include <stdio.h>
#include <string.h>

int main(int argc, char **argv)
{
    if(argc < 2) {
        printf("%s file\n", argv[0]);
        return 0;
    }
    int   exp;
    float coe;
    char line[128];
    FILE *fp = fopen(argv[1], "r");
    if(NULL == fp) {
        perror("fopen");
        return -1;
    }
    while(!feof(fp)) {
        memset(line, 0, sizeof(line));
        fgets(line, 128, fp);
        printf("%s", line);
    }
    fclose(fp);
    return 0;
}
