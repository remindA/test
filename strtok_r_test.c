#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int parse_auth_table_fix_entry(char *auth_table, const char *delim);
int main(int argc, char *argv[])
{
    char string[] = "1#2#3#;a#b#c#;A#B#C#;";
    parse_auth_table_fix_entry(string, ";");

    return 0;
}

int parse_auth_table_fix_entry(char *auth_table, const char *delim)
{
    char *str, *token;
    char *saveptr;

    int i;
    for(i = 1, str = auth_table; ; i++, str = NULL)
    {
        token = strtok_r(str, delim, &saveptr);
        if(token == NULL)
            return 0;
        printf("%s\n", token);
    }
    return 0;
}
