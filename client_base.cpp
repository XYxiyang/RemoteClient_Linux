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
        line.erase(line.find("#"));//����ע��
        if(line.find("������IP��ַ")!=std::string::npos&&!ipadr.length()){
            givevalue("������IP��ַ",line,ipadr);
        }
        if(line.find("�˿ں�")!=std::string::npos&&port=="43597"){
            givevalue("�˿ں�",line,port);
        }
        if(line.find("DEBUG����")!=std::string::npos&&!debug.length()){
            givevalue("DEBUG����",line,debug);
        }
        if(line.find("���̽��ճɹ����˳�")!=std::string::npos&&exit==-1){
            givevalue("���̽��ճɹ����˳�",line,exit);
        }
        if(line.find("��С�����ն�����")!=std::string::npos&&mindev==5){
            givevalue("��С�����ն�����",line,mindev,3,10,5);
        }
        if(line.find("��������ն�����")!=std::string::npos&&maxdev==5){
            givevalue("��������ն�����",line,maxdev,10,50,28);
        }
        if(line.find("ÿ���ն���С��������")!=std::string::npos&&minscr==3){
            givevalue("ÿ���ն���С��������",line,minscr,1,3,3);
        }
        if(line.find("ÿ���ն������������")!=std::string::npos&&minscr==10){
            givevalue("ÿ���ն������������",line,minscr,4,16,10);
        }
        if(line.find("ɾ����־�ļ�")!=std::string::npos&&del==-1){
            givevalue("ɾ����־�ļ�",line,del);
        }
        if(line.find("DEBUG��Ļ��ʾ")!=std::string::npos&&debugscr==-1){
            givevalue("DEBUG��Ļ��ʾ",line,debugscr);
        }
        if(line.find("�����ѽ�����")!=std::string::npos&&maxfork==300){
            givevalue("�����ѽ�����",line,maxfork);
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
        return NOTIEXPIRED ;//֤�����
    if(!strcmp(origin.c_str(),AUTHSTR))//��֤����
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
            writelog(gettime()+" ["+cdevid+"]�յ�ϵͳ��Ϣ����",1,order);
            sendsysinfo(cdevid,socket_desc,&forsend[pos],pos);
            writelog(gettime()+" ["+cdevid+"]׼������ϵͳ��Ϣ",1,order);
        }
        if(recgmsgtype(&buff[i])==GETSETINFO){
            writelog(gettime()+" ["+cdevid+"]�յ�������Ϣ����",1,order);
            sendsetinfo(cdevid,socket_desc,&forsend[pos],pos);
            writelog(gettime()+" ["+cdevid+"]׼������������Ϣ",1,order);
        }
        if(recgmsgtype(&buff[i])==GETPROCINFO){
            writelog(gettime()+" ["+cdevid+"]�յ�������Ϣ����",1,order);
            sendprocinfo(cdevid,socket_desc,&forsend[pos],pos);
            writelog(gettime()+" ["+cdevid+"]׼�����ͽ�����Ϣ",1,order);
        }
        if(recgmsgtype(&buff[i])==GETETHINFO){
            writelog(gettime()+" ["+cdevid+"]�յ���̫����Ϣ����",1,order);
            sendethinfo(cdevid,socket_desc,(int)buff[i+5],devid,&forsend[pos],pos);
            writelog(gettime()+" ["+cdevid+"]׼��������̫����Ϣ",1,order);
        }
        if(recgmsgtype(&buff[i])==GETUSBINFO){
            writelog(gettime()+" ["+cdevid+"]�յ�usb��Ϣ����",1,order);
            sendusbinfo(cdevid,socket_desc,devid,&forsend[pos],pos);
            writelog(gettime()+" ["+cdevid+"]׼�������Ƿ����usb��Ϣ",1,order);
        }
        if(recgmsgtype(&buff[i])==GETUSBFILEINFO){
            writelog(gettime()+" ["+cdevid+"]�յ�usb�ļ��б���Ϣ����",1,order);
            sendusbfileinfo(cdevid,socket_desc,&forsend[pos],pos);
            writelog(gettime()+" ["+cdevid+"]׼������usb�ļ��б���Ϣ",1,order);
        }
        if(recgmsgtype(&buff[i])==GETPRINTINFO){
            writelog(gettime()+" ["+cdevid+"]�յ���ӡ����Ϣ����",1,order);
            sendprintinfo(cdevid,socket_desc,devid,&forsend[pos],pos);
            writelog(gettime()+" ["+cdevid+"]׼�����ʹ�ӡ����Ϣ",1,order);
        }
        if(recgmsgtype(&buff[i])==GETROWINFO){
            writelog(gettime()+" ["+cdevid+"]�յ���ӡ������Ϣ����",1,order);
            sendrowinfo(cdevid,socket_desc,&forsend[pos],pos);
            writelog(gettime()+" ["+cdevid+"]׼�����ʹ�ӡ������Ϣ",1,order);
        }
        if(recgmsgtype(&buff[i])==GETTTYINFO){
            writelog(gettime()+" ["+cdevid+"]�յ��ն���Ϣ����",1,order);
            total=sendttyinfo(cdevid,socket_desc,devid,mindev,maxdev,&forsend[pos],pos);
            writelog(gettime()+" ["+cdevid+"]׼�������ն˷�����Ϣ",1,order);
        }
        if(recgmsgtype(&buff[i])==GETDEVSETINFO){
            writelog(gettime()+" ["+cdevid+"]�յ����ն���Ϣ����",1,order);
            srcnum+=senddevsetinfo(cdevid,socket_desc,(unsigned char)buff[i+5],minscr,maxscr,ipadr,port,&forsend[pos],pos);
            writelog(gettime()+" ["+cdevid+"]׼���������ն˺�������Ϣ",1,order);
        }
        if(recgmsgtype(&buff[i])==GETIPSETINFO){
            writelog(gettime()+" ["+cdevid+"]�յ�IP�ն���Ϣ����",1,order);
            srcnum+=sendipsetinfo(cdevid,socket_desc,(unsigned char)buff[i+5],minscr,maxscr,ipadr,port,&forsend[pos],pos);
            writelog(gettime()+" ["+cdevid+"]׼������IP�ն˺�������Ϣ",1,order);
        }
        if(recgmsgtype(&buff[i])==FINISHED){
            writelog(gettime()+" ["+cdevid+"]�յ�������Ϣ�շ���ɱ���",1,order);
            sendfinish(cdevid,socket_desc,&forsend[pos],pos);
            writelog(gettime()+" ["+cdevid+"]׼������ȫ��Ӧ����Ϣ",1,order);
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

    

    writelog(gettime()+" ��ȡ�����ļ��ɹ�����ʼ����",1,order);
    int t1=time(0);
    for(int i=1;i<=devnum;i++){
        writelog(gettime()+" fork���̿�ʼ",1,order);

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
            writelog(gettime()+" ["+cdevid+"]��ȡ"+cnum+"���ֽڣ�����Ϊ��",1,order);
            writelog(buff,ret_for_read,order);
            authmsg msg;
            authenreq_fromserver(buff,msg);
            msg.emptystr=devid%2;

            int retforcheck=checkauthstrandtime(msg.authstr,msg.randomnum,msg.svrtime);
            
            if(retforcheck==AUTHERROR){
                //��ʾ��֤����
                return 0;
            }
            else if(retforcheck==NOTIEXPIRED){
                //��ʾ����
                return 0;
            }
            else if(msg.mainver<2){
                writelog(gettime()+" ["+cdevid+"]׼��������Ͱ汾����",2,order);
                sendlowestver(cdevid,socket_desc);
                return 0;
            }
            
            writelog(gettime()+" ["+cdevid+"]��֤�ɹ�",1,order);

            writelog(gettime()+" ["+cdevid+"]����116���ֽڣ�����Ϊ��",1,order);
            sendbasicinfo(socket_desc,devid,order);
            int total=0,srcnum=0;

            while(1){
                
                ret_for_read = read(socket_desc, buff, 512);

                if(ret_for_read<=0)
                    break;
                
                memset(cnum,0,10);
                sprintf(cnum,"%d",ret_for_read);
                writelog(gettime()+" ["+cdevid+"]�յ�"+cnum+"���ֽڣ�����Ϊ��",1,order);
                writelog(buff,ret_for_read,order);


                char * forsend=new char[20000];
                int pos=0;
                sendmsgs(ret_for_read,buff,socket_desc,devid,maxdev,
                mindev,maxscr,minscr,ipadr,atoi(port.c_str()),total,srcnum,forsend,pos,cdevid,order);
                
                int ret_for_write=write(socket_desc,forsend,pos);
                memset(cnum,0,10);
                sprintf(cnum,"%d",ret_for_write);
                writelog(gettime()+" ["+cdevid+"]����"+cnum+"���ֽڣ�����Ϊ��",1,order);
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

            writelog(gettime()+" ["+cdevid+"]�շ������������˳�",1,order);

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
    printf("ȫ������������ʱ%ds\n",t2-t1);
    
    return 0;
}