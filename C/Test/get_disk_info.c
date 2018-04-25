#include <stdio.h>
#include <sys/ioctl.h>
#include <linux/hdreg.h>
#include <sys/stat.h>
#include <fcntl.h>

static int
getdiskid (char *hardc)
{
    int fd;
    struct hd_driveid hid;
    fd = open ("/dev/sda", O_RDONLY);
    if (fd < 0)
    {
        return -1;
    }
    if (ioctl (fd, HDIO_GET_IDENTITY, &hid) < 0)
    {
        return -1;
    }
    close (fd);
    sprintf(hardc,"%s", hid.serial_no);
    return 0;
}

int main(void)
{
                 char hardseri[50];
                 getdiskid(hardseri);
                 printf("%s",hardseri);
                 return 0;
}
