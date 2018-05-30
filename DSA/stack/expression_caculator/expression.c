/*
 * =====================================================================================
 *
 *       Filename:  expression.c
 *
 *    Description:  表达式
 *                  prefix-expression
 *                  infix-expression
 *                  suffix-expression
 *
 *        Version:  1.0
 *        Created:  05/27/2018 12:36:49 PM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  YOUR NAME (), 
 *   Organization:  
 *
 * =====================================================================================
 */

/*
 * 解析表达式
 * 转换表达式
 * 表达式求值
 */

enum OPERAND{
    _ADD,
    _MINUS,
    _TIMES,
    _DEVIDE,
    _OPERAND_MAX,
};

operand_t operand_tabs[] = {
    {_ADD, "+"},
    {_MINUS, "-"},
    {_TIMES, "*"},
    {_DEVIDE, "/"},
    {_OPERAND_MAX, NULL}
};


express_t * express_create()
{
    express_t *express = (express_t *)calloc(LEN_EXPRESS_MAX, sizeof(char));
    if(NULL == express) {
        perror("calloc");
        return -1;
    }
    return 1;
}


int express_parse(express_t *express, const char *str)
{
    if(strlen(str) > LEN_EXPRESS_MAX) {
        fprintf(stderr, "expression's length over %d\n", LEN_EXPRESS_MAX);
        return -1;
    }
    /* 清空 */
    stack_clear(express);
    /* 解析入栈 */

    char *c;
    for(c = str; *c != '\0'; c++) {
        if(part_of_express(*c)) {
            stack_push(express, c, sizeof(*c));
        }
    }
    return 1;
}


/* len(to) >= len(from) */
int express_cvrt(express_t *from, express_t *to, int cvrt)
{
    int ret = -1;
    /* 可以使用函数指针 */
    switch(cvrt) {
        case PRE2IN:
        case PRE2SUF:
        case IN2PRE:
        case IN2SUF:
            ret = express_cvrt_in2suf(from, to);
            break;
        case SUF2IN:
        case SUF2PRE:
    }
    return ret;
}

int express_cvrt_in2suf(express_t *from, express_t *to)
{
    stack_clear(to);
    express_t *operand = express_create();
    if(NULL == operand) {
        printf("cannot create express\n");
        return -1;
    }
    void *pos;
    stack_for_each(pos, from) {
        char *opr = (char *)pos;
        if(is_operator(*opr)) {
            stack_push(to, opr, sizeof(*opr));
        }
        else if(is_left_bracket(*opr)) {
            stack_push(operand, opr, sizeof(*opr));
        }
        else if(is_right_bracket(*opr)) {
            while(1) {
                char c;
                stack_pop(operand, &c, sizeof(c));
                if(is_left_bracket(c)) {
                    break;
                }
                stack_push(to, &c, sizeof(c);
            }
        }
        else {
            if(stack_empty(operand) || is_left_bracket((char)(operand->top))) {
                stack_push(operand, opr, sizeof(*opr));
            }
            else if(pr_higher_than(*opr, (char)(operand->top))) {
                stack_push(operand, opr, sizeof(*opr));
            }
            else if(pr_higher_than((char)(operand->top), *opr)) {
                while()
            }
        }
    }
}


int express_calc(stack_t *express, double *val)
{

    return 1;
}

int part_of_express(char c)
{
    return 1;
}

int is_left_bracket(const char c)
{
    return (c == '(');
}


int is_right_bracket(const char c)
{
    return (c == ')');
}

