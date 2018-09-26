/*
 * =====================================================================================
 *
 *       Filename:  request_main.c
 *
 *    Description:  模拟连续发送http请求,或响应
 *
 *        Version:  1.0
 *        Created:  2018年09月21日 13时40分56秒
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  YOUR NAME (), 
 *   Organization:  
 *
 * =====================================================================================
 */
/* 使用网络调试助手来接手数据，我们只负责发送 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "utils_net.h"



const char *http_get = 
"XXX /doc/ui/images/My97DatePicker/navLeft.gif XXX/1.1\r\n"
"Host: 10.10.10.119:8080\r\n"
"User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:62.0) Gecko/20100101 Firefox/62.0\r\n"
"Accept: */*\r\n"
"Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2\r\n"
"Accept-Encoding: gzip, deflate\r\n"
"Referer: http://10.10.10.119:8080/doc/ui/css/ui.date.css?version=1537432753960\r\n"
"Cookie: language=zh; WebSession=3999e054e761bf430c7b; sdMarkMenu=1_0%3Asystem\r\n"
"Connection: keep-alive\r\n"
"\r\n";

const char *http_put_below_mtu = 
"XXX /ISAPI/Security/sessionHeartbeat XXX/1.1\r\n"
"Host: 10.10.10.119:8080\r\n"
"User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:62.0) Gecko/20100101 Firefox/62.0\r\n"
"Accept: */*\r\n"
"Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2\r\n"
"Accept-Encoding: gzip, deflate\r\n"
"Referer: http://10.10.10.119:8080/doc/page/preview.asp\r\n"
"If-Modified-Since: 0\r\n"
"X-Requested-With: XMLHttpRequest\r\n"
"Cookie: language=zh; WebSession=3999e054e761bf430c7b\r\n"
"Connection: keep-alive\r\n"
"Content-Length: 0\r\n"
"\r\n";

const char *http_post_beyond_mtu = 
"XXX /ISAPI/System/deviceInfo XXX/1.1\r\n"
"Host: 10.10.10.119:8080\r\n"
"User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:62.0) Gecko/20100101 Firefox/62.0\r\n"
"Accept: */*\r\n"
"Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2\r\n"
"Accept-Encoding: gzip, deflate\r\n"
"Referer: http://10.10.10.119:8080/doc/page/config.asp\r\n"
"Content-Type: application/x-www-form-urlencoded; charset=UTF-8\r\n"
"If-Modified-Since: 0\r\n"
"X-Requested-With: XMLHttpRequest\r\n"
"Content-Length: 1509\r\n"
"Cookie: language=zh; WebSession=3999e054e761bf430c7b; sdMarkMenu=1_0%3Asystem; sdMarkTab_1_0=0%3AsettingBasic\r\n"
"Connection: keep-alive\r\n"
"\r\n"
"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n"
"<DeviceInfo version=\"2.0\" xmlns=\"http://www.hikvision.com/ver20/XMLSchema\">\r\n"
"<DeviceInfo version=\"2.0\" xmlns=\"http://www.hikvision.com/ver20/XMLSchema\">\r\n"
"<DeviceInfo version=\"2.0\" xmlns=\"http://www.hikvision.com/ver20/XMLSchema\">\r\n"
"<DeviceInfo version=\"2.0\" xmlns=\"http://www.hikvision.com/ver20/XMLSchema\">\r\n"
"<DeviceInfo version=\"2.0\" xmlns=\"http://www.hikvision.com/ver20/XMLSchema\">\r\n"
"<DeviceInfo version=\"2.0\" xmlns=\"http://www.hikvision.com/ver20/XMLSchema\">\r\n"
"<DeviceInfo version=\"2.0\" xmlns=\"http://www.hikvision.com/ver20/XMLSchema\">\r\n"
"<deviceName>IP CAMERA</deviceName>\r\n"
"<deviceName>IP CAMERA</deviceName>\r\n"
"<deviceName>IP CAMERA</deviceName>\r\n"
"<deviceID>8bde032b-45a0-11b5-8404-a41437c23d97</deviceID>\r\n"
"<deviceDescription>IPCamera</deviceDescription>\r\n"
"<deviceLocation>hangzhou</deviceLocation>\r\n"
"<systemContact>Hikvision.China</systemContact>\r\n"
"<model>DS-2CD3T25D-I3</model>\r\n"
"<serialNumber>DS-2CD3T25D-I320161028AACH666223403</serialNumber>\r\n"
"<macAddress>a4:14:37:c2:3d:97</macAddress>\r\n"
"<firmwareVersion>V5.4.20</firmwareVersion>\r\n"
"<firmwareReleasedDate>build 160726</firmwareReleasedDate>\r\n"
"<encoderVersion>V7.3</encoderVersion>\r\n"
"<encoderReleasedDate>build 160713</encoderReleasedDate>\r\n"
"<bootVersion>V1.3.4</bootVersion>\r\n"
"<bootReleasedDate>100316</bootReleasedDate>\r\n"
"<hardwareVersion>0x0</hardwareVersion>\r\n"
"<deviceType>IPCamera</deviceType>\r\n"
"<telecontrolID>88</telecontrolID>\r\n"
"<supportBeep>false</supportBeep>\r\n"
"<supportVideoLoss>false</supportVideoLoss>\r\n"
"</DeviceInfo>\r\n";

const char *http_head = 
"XXX /ISAPI/System/deviceInfo XXXX/1.1\r\n"
"Host: 10.10.10.119:8080\r\n"
"User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:62.0) Gecko/20100101 Firefox/62.0\r\n"
"Accept: */*\r\n"
"Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2\r\n"
"Accept-Encoding: gzip, deflate\r\n"
"Referer: http://10.10.10.119:8080/doc/page/config.asp\r\n"
"Content-Type: application/x-www-form-urlencoded; charset=UTF-8\r\n"
"If-Modified-Since: 0\r\n"
"X-Requested-With: XMLHttpRequest\r\n"
"Content-Length: 1509\r\n"
"Cookie: language=zh; WebSession=3999e054e761bf430c7b; sdMarkMenu=1_0%3Asystem; sdMarkTab_1_0=0%3AsettingBasic\r\n"
"Connection: keep-alive\r\n"
"\r\n";
const char *http_body = 
"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n"
"<DeviceInfo version=\"2.0\" xmlns=\"http://www.hikvision.com/ver20/XMLSchema\">\r\n"
"<DeviceInfo version=\"2.0\" xmlns=\"http://www.hikvision.com/ver20/XMLSchema\">\r\n"
"<DeviceInfo version=\"2.0\" xmlns=\"http://www.hikvision.com/ver20/XMLSchema\">\r\n"
"<DeviceInfo version=\"2.0\" xmlns=\"http://www.hikvision.com/ver20/XMLSchema\">\r\n"
"<DeviceInfo version=\"2.0\" xmlns=\"http://www.hikvision.com/ver20/XMLSchema\">\r\n"
"<DeviceInfo version=\"2.0\" xmlns=\"http://www.hikvision.com/ver20/XMLSchema\">\r\n"
"<DeviceInfo version=\"2.0\" xmlns=\"http://www.hikvision.com/ver20/XMLSchema\">\r\n"
"<deviceName>IP CAMERA</deviceName>\r\n"
"<deviceName>IP CAMERA</deviceName>\r\n"
"<deviceName>IP CAMERA</deviceName>\r\n"
"<deviceID>8bde032b-45a0-11b5-8404-a41437c23d97</deviceID>\r\n"
"<deviceDescription>IPCamera</deviceDescription>\r\n"
"<deviceLocation>hangzhou</deviceLocation>\r\n"
"<systemContact>Hikvision.China</systemContact>\r\n"
"<model>DS-2CD3T25D-I3</model>\r\n"
"<serialNumber>DS-2CD3T25D-I320161028AACH666223403</serialNumber>\r\n"
"<macAddress>a4:14:37:c2:3d:97</macAddress>\r\n"
"<firmwareVersion>V5.4.20</firmwareVersion>\r\n"
"<firmwareReleasedDate>build 160726</firmwareReleasedDate>\r\n"
"<encoderVersion>V7.3</encoderVersion>\r\n"
"<encoderReleasedDate>build 160713</encoderReleasedDate>\r\n"
"<bootVersion>V1.3.4</bootVersion>\r\n"
"<bootReleasedDate>100316</bootReleasedDate>\r\n"
"<hardwareVersion>0x0</hardwareVersion>\r\n"
"<deviceType>IPCamera</deviceType>\r\n"
"<telecontrolID>88</telecontrolID>\r\n"
"<supportBeep>false</supportBeep>\r\n"
"<supportVideoLoss>false</supportVideoLoss>\r\n"
"</DeviceInfo>\r\n";

int main(int argc, char **argv)
{
    /* 建立套接字 */
    char *ip = argv[1];
    unsigned short port = (unsigned short)atoi(argv[2]);
    int fd = sock_connect(ip, port); 
    if(fd < 0) {
        return -1;
    }
    int ret;
    ret = write(fd, http_get, strlen(http_get));
    sleep(1);
    ret = write(fd, http_put_below_mtu, strlen(http_put_below_mtu));
    sleep(1);
    ret = write(fd, http_post_beyond_mtu, strlen(http_post_beyond_mtu));
    sleep(1);
    ret = write(fd, http_head, strlen(http_head));
    sleep(1);
    ret = write(fd, http_body, strlen(http_body));
    close(fd);
    return 0;
    /* 发送http报文 */
}




