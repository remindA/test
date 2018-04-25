#include <stdio.h>
#define CANCEL      0
#define BLACK       30
#define RED         31
#define GREEN       32
#define YELLOW      33
#define BLUE        34
#define PURPLE      35
#define DARK_GREEN  36
#define WHITE       37
#define FONT_(x)    printf("\033[%dm", (x))

int main(int argc, char **argv)
{
    //颜色开始
    FONT_(PURPLE); 
    printf("Hello world\n");
    FONT_(BLUE); 
    printf("Hello world\n");
    FONT_(RED); 
    printf("Hello world\n");

    //取消颜色设置
    FONT_(CANCEL);
    return 0;
}
