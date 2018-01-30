/*
 * =====================================================================================
 *
 *       Filename:  ipcrm.c
 *
 *    Description:  
 *
 *        Version:  1.0
 *        Created:  2018年01月22日 16时32分13秒
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  YOUR NAME (), 
 *   Organization:  
 *
 * =====================================================================================
 */

#include <stdio.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/sem.h>
#include <sys/shm.h>
#include <sys/msg.h>

void usage(const char *prg)
{
        printf("Usage: %s [option] [semid/shmid/msqid/]\n", prg);
        printf("[option]\n");
        printf("\t\t-s semid\n");
        printf("\t\t-m shmid\n");
        printf("\t\t-q msqid\n");
}

int main(int argc, char **argv)
{
    if(argc != 3) {
        usage(argv);
        return 0;
    }
    int id = atoi(argv[2]);
    printf("id = %d\n", id);
    switch(argv[1][1]) {
        case 's':
            if(semctl(id, IPC_RMID, 0) < 0)
                perror("semctl()");
            break;
        case 'm':
            if(shmctl(id, IPC_RMID, 0) < 0)
                perror("shmctl()");
            break;
        case 'q':
            if(msgctl(id, IPC_RMID, 0) < 0)
                perror("msgctl()");
            break;
        default:
            usage(argv);
            break;
    }
    return 0;
}
