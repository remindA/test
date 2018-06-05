#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>



void action_a2a()
{
    printf("Action _STATE_A To _STATE_A\n");
}

void action_a2b()
{
    printf("Action _STATE_A To _STATE_B\n");
}

void action_a2c()
{
    printf("Action _STATE_A To _STATE_C\n");

}

void action_b2a()
{
    printf("Action _STATE_B To _STATE_A\n");
}

void action_b2b()
{
    printf("Action _STATE_B To _STATE_B\n");
}

void action_b2c()
{
    printf("Action _STATE_B To _STATE_C\n");
}

void action_c2a()
{
    printf("Action _STATE_C To _STATE_A\n");
}

void action_c2b()
{
    printf("Action _STATE_C To _STATE_B\n");
}


void action_c2c()
{
    printf("Action _STATE_C To _STATE_C\n");
}




enum {
    _STATE_A = 0,
    _STATE_B,
    _STATE_C,
    _STATE_MAX
};


/* as array index */
enum {
    _EVENT_A2A = 0,
    _EVENT_A2B,
    _EVENT_A2C,
    _EVENT_B2A,
    _EVENT_B2B,
    _EVENT_B2C,
    _EVENT_C2A,
    _EVENT_C2B,
    _EVENT_C2C,
    _EVENT_MAX
};

typedef void (*action_fun)(void);

typedef struct {
    int event;
    int cur_st;
    action_fun action;
    int next_st;
}fsm_entry_t;

fsm_entry_t event_table[_EVENT_MAX] = {
    {_EVENT_A2A, _STATE_A, action_a2a, _STATE_A},
    {_EVENT_A2B, _STATE_A, action_a2b, _STATE_B},
    {_EVENT_A2C, _STATE_A, action_a2c, _STATE_C},
    {_EVENT_B2A, _STATE_B, action_b2a, _STATE_A},
    {_EVENT_B2B, _STATE_B, action_b2b, _STATE_B},
    {_EVENT_B2C, _STATE_B, action_b2c, _STATE_C},
    {_EVENT_C2A, _STATE_C, action_c2a, _STATE_A},
    {_EVENT_C2B, _STATE_C, action_c2b, _STATE_B},
    {_EVENT_C2C, _STATE_C, action_c2c, _STATE_C},
};

typedef struct {
    int state;
    fsm_entry_t *table;
}fsm_t;

const char *state_str[] = {
    [_STATE_A] = "[State A]",
    [_STATE_B] = "[State B]",
    [_STATE_C] = "[State C]"
};

void state_transfer(fsm_t *fsm, int next_st)
{
    fsm->state = next_st;
}
/* 
 * 0: a2a
 * 1: a2b
 * 2: a2c
 *
 * 3: b2a
 * 4: b2b
 * 5: b2c
 *
 * 6: c2a
 * 7: c2b
 * 8: c2c
 */

int get_event(char c)
{
    return c - '0';
}


void fsm_init(fsm_t *fsm, fsm_entry_t *table, int state)
{
    memset(fsm, 0, sizeof(*fsm));
    fsm->table = table;
    fsm->state = state;
}

int main(int argc, char **argv)
{
    fsm_t fsm;
    fsm_init(&fsm, event_table ,_STATE_A);
    while(1){
        char c = getchar();
        /* 根据当前state */
        int event = get_event(c);
        if(event >= _EVENT_MAX) {
            printf("Current State is %s, Cannot Handle Such Event\n", state_str[fsm.state]);
            break;
        }
        /*
         * 根据current state, do actions, transfer state
         */
        if(fsm.state == fsm.table[event].cur_st) {
            printf("Current State is %s\n", state_str[fsm.state]);
            fsm.table[event].action();
            state_transfer(&fsm, fsm.table[event].next_st);
            printf("Now, Current State is %s\n", state_str[fsm.state]);
        }
    }
}
