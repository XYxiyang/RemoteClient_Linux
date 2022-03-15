#include"../include/common.h"
#include"../include/types.h"
#include"../include/key.h"
#include"../include/clientmsg.h"
#include<unistd.h>
#include<stdlib.h>
#include<signal.h>
#include<sys/param.h>
#include<sys/stat.h>
#include<wait.h>
#include<time.h>
#include<stdio.h>
#include<fstream>
#include<syslog.h>
#include<sys/types.h>
#include<sys/prctl.h>
#include<string>
#include<cstring>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <ctime>

void readconf(std::string &ipadr,std::string &port,std::string &debug,
    int &exit,int &mindev,int &maxdev ,int &minscr,
    int &maxscr,int &debugscr,int &del,int& maxfork){
    std::ifstream file;
    file.open("ts.conf",std::ios::in);
    
    char str[256];
    while(!file.eof()){
        file.getline(str,256);
        if(!file.good())
            break;  
        std::string line=str;
        line.erase(line.find("#"));//过滤注释
        if(line.find("服务器IP地址")!=std::string::npos&&!ipadr.length()){
            givevalue("服务器IP地址",line,ipadr);
        }
        if(line.find("端口号")!=std::string::npos&&port=="43597"){
            givevalue("端口号",line,port);
        }
        if(line.find("DEBUG设置")!=std::string::npos&&!debug.length()){
            givevalue("DEBUG设置",line,debug);
        }
        if(line.find("进程接收成功后退出")!=std::string::npos&&exit==-1){
            givevalue("进程接收成功后退出",line,exit);
        }
        if(line.find("最小配置终端数量")!=std::string::npos&&mindev==5){
            givevalue("最小配置终端数量",line,mindev,3,10,5);
        }
        if(line.find("最大配置终端数量")!=std::string::npos&&maxdev==5){
            givevalue("最大配置终端数量",line,maxdev,10,50,28);
        }
        if(line.find("每个终端最小虚屏数量")!=std::string::npos&&minscr==3){
            givevalue("每个终端最小虚屏数量",line,minscr,1,3,3);
        }
        if(line.find("每个终端最大虚屏数量")!=std::string::npos&&minscr==10){
            givevalue("每个终端最大虚屏数量",line,minscr,4,16,10);
        }
        if(line.find("删除日志文件")!=std::string::npos&&del==-1){
            givevalue("删除日志文件",line,del);
        }
        if(line.find("DEBUG屏幕显示")!=std::string::npos&&debugscr==-1){
            givevalue("DEBUG屏幕显示",line,debugscr);
        }
        if(line.find("最大分裂进程数")!=std::string::npos&&maxfork==300){
            givevalue("最大分裂进程数",line,maxfork);
        }
    }
    file.close();
}

std::string cutpackage(int startpos,int endpos,const char* buff){
    std::string ret;
    for(int i=startpos;i<=endpos;i++)
        ret+=buff[i];
    return ret;
}

std::string reverseseq(int startpos,int endpos,const char* buff){
    std::string ret;
    for(int i=endpos;i>=startpos;i--)
        ret+=buff[i];
    return ret;
}

bool compstrwithnum(const std::string str,const int*num,int digits){
    if(str.length()<digits)
        return false;
    for(int i=0;i<digits;i++){
        if((unsigned char)str[i]!=num[i])
            return false;
    }
    return true;
}

int recgmsgtype(const char * buff){
    std::string header=cutpackage(0,1,buff);
    int seq[3]={17,1,0};
    if(compstrwithnum(header,seq,2))
        return AUTHFORMSERVER;

    seq[1]=2;
    if(compstrwithnum(header,seq,2))
        return GETSYSINFO;

    seq[1]=3;
    if(compstrwithnum(header,seq,2))
        return GETSETINFO;

    seq[1]=4;
    if(compstrwithnum(header,seq,2))
        return GETPROCINFO;
    
    seq[1]=5;
    if(compstrwithnum(header,seq,2))
        return GETETHINFO;

    seq[1]=7;
    if(compstrwithnum(header,seq,2))
        return GETUSBINFO;

    seq[1]=12;
    if(compstrwithnum(header,seq,2))
        return GETUSBFILEINFO;

    seq[1]=8;
    if(compstrwithnum(header,seq,2))
        return GETPRINTINFO;

    seq[1]=13;
    if(compstrwithnum(header,seq,2))
        return GETROWINFO;

    seq[1]=9;
    if(compstrwithnum(header,seq,2))
        return GETTTYINFO;
    
    seq[1]=10;
    if(compstrwithnum(header,seq,2))
        return GETDEVSETINFO;
    
    seq[1]=11;
    if(compstrwithnum(header,seq,2))
        return GETIPSETINFO;

    seq[1]=255;
    if(compstrwithnum(header,seq,2))
        return FINISHED;
    
    return UNKNOWN;
}

int returnval(int startpos,int endpos,const char*buff){
    int val=0;
    for(int i=startpos;i<=endpos;i++){
        val*=256;
        val+=(unsigned char)buff[i];
        //printf("%ld\n",(unsigned char)buff[i]);
    }
    return val;
}

void authenreq_fromserver(const char* buff,authmsg&msg){
    msg.lenwithouthead=returnval(6,7,buff);
    msg.mainver=returnval(8,9,buff);
    msg.subver1=returnval(10,10,buff);
    msg.subver2=returnval(11,11,buff);
    msg.reconinterval=returnval(12,13,buff);
    msg.resendinterval=returnval(14,15,buff);
    msg.authstr=cutpackage(20,51,buff);
    msg.randomnum=returnval(52,55,buff);
    msg.svrtime=returnval(56,59,buff);
}

int checkauthstrandtime(const std::string authstr,const int randomnum,const int svrtime){
    std::string origin;
    int pos=randomnum%4093;
    for(int i=0;i<32;i++){
        origin+=(char)((int)authstr[i]^secret[pos]);
        pos=++pos%4093;
    }
    int origintime=svrtime^0xFFFFFFFF;
    if(origintime<1483200000)     
        return NOTIEXPIRED ;//证书过期
    if(!strcmp(origin.c_str(),AUTHSTR))//验证错误
        return OK;
    else
        return AUTHERROR;
    
}

void sendmsgs(int ret_for_read,const char*buff,
    int socket_desc,int devid,int maxdev,int mindev,
    int maxscr,int minscr,
    std::string ipadr,int port,int&total
    ,int &srcnum,char * forsend,int&pos,const char*cdevid,int*order){
    for(int i=0;i<ret_for_read;i+=8){
        
        if(recgmsgtype(&buff[i])==GETSYSINFO){
            writelog(gettime()+" ["+cdevid+"]收到系统信息请求",1,order);
            sendsysinfo(cdevid,socket_desc,&forsend[pos],pos);
            writelog(gettime()+" ["+cdevid+"]准备发送系统信息",1,order);
        }
        if(recgmsgtype(&buff[i])==GETSETINFO){
            writelog(gettime()+" ["+cdevid+"]收到配置信息请求",1,order);
            sendsetinfo(cdevid,socket_desc,&forsend[pos],pos);
            writelog(gettime()+" ["+cdevid+"]准备发送配置信息",1,order);
        }
        if(recgmsgtype(&buff[i])==GETPROCINFO){
            writelog(gettime()+" ["+cdevid+"]收到进程信息请求",1,order);
            sendprocinfo(cdevid,socket_desc,&forsend[pos],pos);
            writelog(gettime()+" ["+cdevid+"]准备发送进程信息",1,order);
        }
        if(recgmsgtype(&buff[i])==GETETHINFO){
            writelog(gettime()+" ["+cdevid+"]收到以太口信息请求",1,order);
            sendethinfo(cdevid,socket_desc,(int)buff[i+5],devid,&forsend[pos],pos);
            writelog(gettime()+" ["+cdevid+"]准备发送以太口信息",1,order);
        }
        if(recgmsgtype(&buff[i])==GETUSBINFO){
            writelog(gettime()+" ["+cdevid+"]收到usb信息请求",1,order);
            sendusbinfo(cdevid,socket_desc,devid,&forsend[pos],pos);
            writelog(gettime()+" ["+cdevid+"]准备发送是否存在usb信息",1,order);
        }
        if(recgmsgtype(&buff[i])==GETUSBFILEINFO){
            writelog(gettime()+" ["+cdevid+"]收到usb文件列表信息请求",1,order);
            sendusbfileinfo(cdevid,socket_desc,&forsend[pos],pos);
            writelog(gettime()+" ["+cdevid+"]准备发送usb文件列表信息",1,order);
        }
        if(recgmsgtype(&buff[i])==GETPRINTINFO){
            writelog(gettime()+" ["+cdevid+"]收到打印口信息请求",1,order);
            sendprintinfo(cdevid,socket_desc,devid,&forsend[pos],pos);
            writelog(gettime()+" ["+cdevid+"]准备发送打印口信息",1,order);
        }
        if(recgmsgtype(&buff[i])==GETROWINFO){
            writelog(gettime()+" ["+cdevid+"]收到打印队列信息请求",1,order);
            sendrowinfo(cdevid,socket_desc,&forsend[pos],pos);
            writelog(gettime()+" ["+cdevid+"]准备发送打印队列信息",1,order);
        }
        if(recgmsgtype(&buff[i])==GETTTYINFO){
            writelog(gettime()+" ["+cdevid+"]收到终端信息请求",1,order);
            total=sendttyinfo(cdevid,socket_desc,devid,mindev,maxdev,&forsend[pos],pos);
            writelog(gettime()+" ["+cdevid+"]准备发送终端服务信息",1,order);
        }
        if(recgmsgtype(&buff[i])==GETDEVSETINFO){
            writelog(gettime()+" ["+cdevid+"]收到哑终端信息请求",1,order);
            srcnum+=senddevsetinfo(cdevid,socket_desc,(unsigned char)buff[i+5],minscr,maxscr,ipadr,port,&forsend[pos],pos);
            writelog(gettime()+" ["+cdevid+"]准备发送哑终端和虚屏信息",1,order);
        }
        if(recgmsgtype(&buff[i])==GETIPSETINFO){
            writelog(gettime()+" ["+cdevid+"]收到IP终端信息请求",1,order);
            srcnum+=sendipsetinfo(cdevid,socket_desc,(unsigned char)buff[i+5],minscr,maxscr,ipadr,port,&forsend[pos],pos);
            writelog(gettime()+" ["+cdevid+"]准备发送IP终端和虚屏信息",1,order);
        }
        if(recgmsgtype(&buff[i])==FINISHED){
            writelog(gettime()+" ["+cdevid+"]收到所以信息收发完成报文",1,order);
            sendfinish(cdevid,socket_desc,&forsend[pos],pos);
            writelog(gettime()+" ["+cdevid+"]准备发送全部应答信息",1,order);
        }
    }
}

int main(int argc,char**argv){

    std::string ipadr,port="43597",debug;
    int exit=-1,mindev=5,maxdev=28,minscr=3,maxscr=10,debugscr=-1,del=-1,maxfork=300;

    readconf(ipadr,port,debug,exit,mindev,maxdev,minscr,maxscr,debugscr,del,maxfork);
    std::string startid=argv[1];
    int devnum=atoi(argv[2]);
    
    int reused=0,subs=0;
    int order[7]={0};
    for(int i=1;i<=6;i++){
        order[i]=debug[i-1]-'0';
    }

    

    writelog(gettime()+" 读取配置文件成功，开始运行",1,order);
    int t1=time(0);
    for(int i=1;i<=devnum;i++){
        writelog(gettime()+" fork进程开始",1,order);

        if(subs-reused>300){
            i--;
            while(waitpid(-1,NULL,WNOHANG)>0)
                reused++;
            continue;
        }
        
        pid_t pid;
        pid=fork();

        if(pid<0){
            printf("error when forking\n");
            return 0;
        }

        else if(pid>0){
            subs++;
            int status=0;
            while(waitpid(-1,&status,WNOHANG)>0)
                reused++;
            //printf("status=%d\n",status);
        }
        else if(pid==0){
            srand((unsigned int)(time(0)));
            int devid=atoi(startid.c_str())+i;
            if(i%200==0)
                printf("this is the %dth sub\n",i);
            //prctl(PR_SET_PDEATHSIG, SIGKILL);
            int socket_desc;
            struct sockaddr_in server;
            char* message;

            socket_desc=socket(AF_INET,SOCK_STREAM,0);
            if(socket_desc==-1){
                printf("Failed to create socket\n");
                return 0;
            }//create socket

            server.sin_addr.s_addr = inet_addr(ipadr.c_str());
            server.sin_family = AF_INET;
            server.sin_port = htons(atoi(port.c_str()));

            //printf("%d,%s\n",atoi(port.c_str()),ipadr.c_str());
            int retforcon=connect(socket_desc,(struct sockaddr*)&server,sizeof(server));
            //printf("%d,%s\n",atoi(port.c_str()),ipadr.c_str());
            if(retforcon<0){
                printf("Connect error\n");
                return 0;
            }

            char cdevid[10]={0},cnum[10]={0};
            sprintf(cdevid,"%d",cdevid);
            writelog(gettime()+" ["+cdevid+"]Connected OK",1,order);
            //else printf("Connected\n");

            char buff[512]={0};
            int ret_for_read = read(socket_desc, buff, 512);

            sprintf(cnum,"%d",ret_for_read);
            writelog(gettime()+" ["+cdevid+"]读取"+cnum+"个字节，数据为：",1,order);
            writelog(buff,ret_for_read,order);
            authmsg msg;
            authenreq_fromserver(buff,msg);
            msg.emptystr=devid%2;

            int retforcheck=checkauthstrandtime(msg.authstr,msg.randomnum,msg.svrtime);
            
            if(retforcheck==AUTHERROR){
                //提示认证错误
                return 0;
            }
            else if(retforcheck==NOTIEXPIRED){
                //提示过期
                return 0;
            }
            else if(msg.mainver<2){
                writelog(gettime()+" ["+cdevid+"]准备发送最低版本请求",2,order);
                sendlowestver(cdevid,socket_desc);
                return 0;
            }
            
            writelog(gettime()+" ["+cdevid+"]认证成功",1,order);

            writelog(gettime()+" ["+cdevid+"]发送116个字节，数据为：",1,order);
            sendbasicinfo(socket_desc,devid,order);
            int total=0,srcnum=0;

            while(1){
                
                ret_for_read = read(socket_desc, buff, 512);

                if(ret_for_read<=0)
                    break;
                
                memset(cnum,0,10);
                sprintf(cnum,"%d",ret_for_read);
                writelog(gettime()+" ["+cdevid+"]收到"+cnum+"个字节，数据为：",1,order);
                writelog(buff,ret_for_read,order);


                char * forsend=new char[20000];
                int pos=0;
                sendmsgs(ret_for_read,buff,socket_desc,devid,maxdev,
                mindev,maxscr,minscr,ipadr,atoi(port.c_str()),total,srcnum,forsend,pos,cdevid,order);
                
                int ret_for_write=write(socket_desc,forsend,pos);
                memset(cnum,0,10);
                sprintf(cnum,"%d",ret_for_write);
                writelog(gettime()+" ["+cdevid+"]发送"+cnum+"个字节，数据为：",1,order);
                writelog(forsend,ret_for_write,order,false);
                delete[] forsend;
            }

            //printf("%dth over\n",i);

            char devidc[20]={0};
            sprintf(devidc,"%d",devid);
            std::string text;
            text.append(gettime());
            text.append("\t");
            text.append(devidc);
            text.append("\t1\t");
            char totalc[20]={0};
            sprintf(totalc,"%d",total);
            text.append(totalc);
            text.append("\t");
            char srcnumc[20];
            sprintf(srcnumc,"%d",srcnum);
            text.append(srcnumc);
            writexls(text);

            writelog(gettime()+" ["+cdevid+"]收发结束，进程退出",1,order);

            //printf("reused=%d\n",reused);
            return 0;
        }
        
        
    }
    
    while(1){
        while(waitpid(-1,NULL,WNOHANG)>0)
            reused++;
        if(reused==devnum){
            printf("all over\n");
            break;
        }
    }


    int t2=time(0);
    printf("全部结束，共用时%ds\n",t2-t1);
    
    return 0;
}