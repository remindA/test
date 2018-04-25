#include <stdio.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <string.h>
#include <limits.h>
#include <stdlib.h>
#include <unistd.h>


int main()
{
	struct sockaddr_un localun;
	char path[64] = "niu";
	char rl_path[128] = {0};
	
	bzero(&localun, sizeof(localun));
	if(realpath(path, rl_path) != NULL)
		unlink(rl_path);
	printf("rl_path=%s\n", rl_path);

	localun.sun_family = AF_UNIX;
	strncpy(localun.sun_path, rl_path, sizeof(localun));
	int sockfd_un = socket(AF_LOCAL, SOCK_DGRAM, 0);
	if(sockfd_un < 0)
	{
		perror("socket");
		exit(1);
	}
	if(bind(sockfd_un, (struct sockaddr *)&localun, sizeof(localun)) < 0)
	{
		perror("bind");
		exit(1);
	}
	printf("localun.sun_path=%s\n", localun.sun_path);

	return 0;
}
	
