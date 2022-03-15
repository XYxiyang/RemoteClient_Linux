#include<stdio.h>
#include<string>
#include<cstring>
#include<fstream>
#include<time.h>
#include"../include/clientmsg.h"
#include"../include/types.h"
#include"../include/common.h"
#include"../include/key.h"

void writebuff(char*buff,int startpos,int endpos,int val,int digits){
    if(digits==1)
        buff[startpos]=val;
    else if(digits==2){
        buff[startpos]=val>>8;
        buff[endpos]=(val<<24)>>24;
    }
    else if(digits==4){
        buff[startpos]=val>>24;
        buff[startpos+1]=(val<<8)>>24;
        buff[startpos+2]=(val<<16)>>24;
        buff[startpos+3]=(val<<24)>>24;
    }
}

int sendlowestver(const char*cdevid,int socket_desc){
    char buff[12]={91,0,0,12,0,0,0,4,0,2,0,0};
    write(socket_desc,buff,12);

    
    return OK;
}

void preservenum(std::string &line){
    for(int i=0;i<line.length();i++){
        if(line[i]>'9'||line[i]<'0'){
            line.erase(i,1);
            i--;
        }
    }
}

int sendbasicinfo(int socket_desc,int devid,int*order){
    char text[116]={0};
    text[0]=0x91;
    text[1]=1;
    text[2]=0;
    text[3]=116;
    text[4]=0;
    text[5]=0;
    text[6]=0;
    text[7]=108;


    std::ifstream file;
    file.open("/proc/cpuinfo",std::ios::in);

    char buff[256]={0};
    int cpuhz;
    while(!file.eof()){
        file.getline(buff,256);
        if(!file.good())
            break;  
        std::string line=buff;
        if(line.find("cpu MHz")!=std::string::npos){
            givevalue("cpu MHz",line,cpuhz);
            break;
        }
    }

    file.close();
    text[9]=cpuhz%256;
    text[8]=cpuhz-cpuhz%256;

    file.open("/proc/meminfo",std::ios::in);

    int ram;
    while(!file.eof()){
        file.getline(buff,256);
        if(!file.good())
            break;  
        std::string line=buff;
        if(line.find("MemTotal")!=std::string::npos){
            preservenum(line);
            ram=atoi(line.c_str());
            ram/=1024;
            break;
        }
    }
    
    file.close();

    text[10]=ram-ram%256;
    text[11]=ram%256;

    short rom=597;
    text[12]=rom-rom%256;
    text[13]=rom%256;

    unsigned short innerid=atoi(SMYID.substr(3,4).c_str());
    text[14]=innerid-innerid%256;
    text[15]=innerid%256;

    std::string groupid=MYNAME;
    sprintf(&text[16],"%s",groupid.c_str());

    std::string devtype=SMYNAMESH+'-'+SMYIDREV;
    sprintf(&text[32],"%s",devtype.c_str());

    std::string softver=SMYID.substr(4,2)+'-'+SMYID.substr(6,2);
    sprintf(&text[48],"%s",softver.c_str());
    
    text[64]=devid%2+1;
    text[65]=0;
    if((devid/10)%3==1)
        text[66]=8;
    else if((devid/10)%3==2)
        text[66]=16;
    else
        text[66]=0;
    text[67]=0;
    text[68]=(devid/100)%2;
    text[69]=(devid/1000)%2;

    text[72]=devid>>24;
    text[73]=(devid<<8)>>24;
    text[74]=(devid<<16)>>24;
    text[75]=(devid<<24)>>24;
    
    text[76]=1;

    unsigned int random_num;
    int pos;
    random_num=(unsigned int)rand();
    pos=random_num%4093;
    sprintf(&text[80],"%s",AUTHSTR);
    text[112]=random_num>>24;
    text[113]=(random_num<<8)>>24;
    text[114]=(random_num<<16)>>24;
    text[115]=(random_num<<24)>>24;


    for(int i=8;i<=111;i++){
        text[i]=text[i]^secret[pos];
        pos=++pos%4093;
    }
    

    writelog(text,116,order,false);
    write(socket_desc,text,116);
    return OK;
}

int sendsysinfo(const char*cdevid,int socket_desc,char * forsend,int&pos){
    char text[28]={0};
    text[0]=0x91;
    text[1]=2;
    text[2]=0;
    text[3]=28;
    text[4]=0;
    text[5]=0;
    text[6]=0;
    text[7]=20;

    std::ifstream file;
    file.open("/proc/stat",std::ios::in);

    char buff[256]={0};
    int user=0,nice=0,sys=0,idle=0;
    unsigned int mem=0;
    file.getline(buff,256);
    std::string line=buff;
    int i=0;
    for(;;i++){
        if(buff[i]<='9'&&buff[i]>='0')
            break;
    }
    for(;;i++){
        user*=10;
        user+=buff[i]-'0';
        if(buff[i]==' ')
            break;
    }
    i++;
    for(;;i++){
        nice*=10;
        nice+=buff[i]-'0';
        if(buff[i]==' ')
            break;
    }
    i++;
    for(;;i++){
        sys*=10;
        sys+=buff[i]-'0';
        if(buff[i]==' ')
            break;
    }
    i++;
    for(;;i++){
        idle*=10;
        idle+=buff[i]-'0';
        if(buff[i]==' ')
            break;
    }
    file.close();

    writebuff(text,8,11,user,4);
    writebuff(text,12,15,nice,4);
    writebuff(text,16,19,sys,4);
    writebuff(text,20,23,idle,4);

    file.open("/proc/meminfo",std::ios::in);
    while(!file.eof()){
        file.getline(buff,256);
        if(!file.good())
            break;  
        std::string line=buff;
        if(line.find("MemFree")!=std::string::npos){
            preservenum(line);
            mem+=atoi(line.c_str());
        }
        if(line.find("MemAvailale")!=std::string::npos){
            preservenum(line);
            mem+=atoi(line.c_str());
        }
        if(line.find("Cached")!=std::string::npos){
            preservenum(line);
            mem+=atoi(line.c_str());
        }
    }

    mem/=1024;
    writebuff(text,24,25,mem,4);

    file.close();

    memcpy(forsend,text,28);
    pos+=28;

    
    return OK;
}

int sendsetinfo(const char*cdevid,int socket_desc,char * forsend,int&pos){


    std::ifstream file;
    file.open("config.dat",std::ios::in|std::ios::binary);

    int length;
    file.seekg(0,std::ios::end);
    length=file.tellg();
    file.seekg(0,std::ios::beg);

    char*buffer=new char[length+9];//'\0'+header+body
    file.read(&buffer[8],length);

    file.close();

    buffer[0]=0x91;
    buffer[1]=3;

    writebuff(buffer,2,3,length+9,2);

    buffer[4]=0;
    buffer[5]=0;

    writebuff(buffer,6,7,length+1,2);

    buffer[length+8]=0;

    memcpy(forsend,buffer,length+9);
    pos+=length+9;


    
    delete[] buffer;
    return OK;
}

int sendprocinfo(const char*cdevid,int socket_desc,char * forsend,int&pos){
    std::ifstream file;
    file.open("process.dat",std::ios::in|std::ios::binary);

    int length;
    file.seekg(0,std::ios::end);
    length=file.tellg();
    file.seekg(0,std::ios::beg);

    char*buffer=new char[length+9];//'\0'+header+body
    file.read(&buffer[8],length);

    file.close();

    buffer[0]=0x91;
    buffer[1]=4;

    writebuff(buffer,2,3,length+9,2);

    buffer[4]=0;
    buffer[5]=0;

    writebuff(buffer,6,7,length+1,2);

    buffer[length+8]=0;

    memcpy(forsend,buffer,length+9);
    pos+=length+9;
    
    delete[] buffer;
    return OK;
}

int sendethinfo(const char*cdevid,int socket_desc,int port,int devid,char * forsend,int&pos){
    char text[132]={0};
    text[0]=0x91;
    text[1]=5;
    text[2]=0;
    text[3]=132;
    text[4]=0;
    text[5]=port;
    text[6]=0;
    text[7]=124;
    text[8]=1;
    text[9]=1;
    text[10]=1;

    text[12]=0;
    text[13]=22;
    text[14]=32;
    text[15]=10;
    text[16]=140;
    text[17]=devid%100;
    text[18]=0;
    text[19]=7;

    text[20]=devid%100,text[21]=168,text[22]=187,text[23]=16;
    text[24]=255,text[25]=255,text[26]=255,text[27]=0;

    text[28]=devid%100,text[29]=168,text[30]=187,text[31]=17;
    text[32]=255,text[33]=255,text[34]=255,text[35]=0;

    text[36]=devid%100,text[37]=168,text[38]=187,text[39]=18;
    text[40]=255,text[41]=255,text[42]=255,text[43]=0;

    text[44]=devid%100,text[45]=168,text[46]=187,text[47]=19;
    text[48]=255,text[49]=255,text[50]=255,text[51]=0;

    text[52]=devid%100,text[53]=168,text[54]=187,text[55]=20;
    text[56]=255,text[57]=255,text[58]=255,text[59]=0;

    text[60]=devid%100,text[61]=168,text[62]=187,text[63]=21;
    text[64]=255,text[65]=255,text[66]=255,text[67]=0;

    std::ifstream file;
    char buff[256]={0};
    file.open("/proc/net/dev",std::ios::in);
    int data[16]={0};

    file.getline(buff,256);
    if(port==1)
        file.getline(buff,256);
    
    for(int i=0,pos=0;i<16;i++){
        for(;buff[pos]>'9'||buff[pos]<'0';pos++);
        for(;buff[pos]>='0'&&buff[pos]<='9';pos++){
            data[i]*=10;
            data[i]+=buff[pos]-'0';
        }
    }
    file.close();
    for(int i=0;i<16;i++){
        writebuff(text,68+i*4,71+i*4,data[i],4);
    }
    


    memcpy(forsend,text,132);
    pos+=132;
    
    return OK;
}

int sendusbinfo(const char*cdevid,int socket_desc,int devid,char * forsend,int&pos){
    char text[12]={0};
    text[0]=0x91;
    text[1]=7;
    text[2]=0;
    text[3]=12;
    text[4]=0;
    text[5]=0;
    text[6]=0;
    text[7]=4;
    text[8]=devid%2;

    memcpy(forsend,text,12);
    pos+=12;
    

    
    return OK;
}

int sendusbfileinfo(const char*cdevid,int socket_desc,char * forsend,int&pos){
    std::ifstream file;
    file.open("usefiles.dat",std::ios::in|std::ios::binary);

    int length;
    file.seekg(0,std::ios::end);
    length=file.tellg();
    file.seekg(0,std::ios::beg);

    char*buffer=new char[length+9];//'\0'+header+body
    file.read(&buffer[8],length);

    file.close();

    buffer[0]=0x91;
    buffer[1]=12;

    writebuff(buffer,2,3,length+9,2);

    buffer[4]=0;
    buffer[5]=0;

    writebuff(buffer,6,7,length+1,2);

    buffer[length+8]=0;


    memcpy(forsend,buffer,length+9);
    pos+=length+9;
    
    
    delete[] buffer;
    return OK;
}

int sendprintinfo(const char*cdevid,int socket_desc,int devid,char * forsend,int&pos){
    char buffer[44]={0};
    
    std::string name="PRN-";
    name.append(MYNAMESH);
    name+='-';
    name.append(SMYID.substr(3,4));

    buffer[0]=0x91;
    buffer[1]=8;

    writebuff(buffer,2,3,44,2);

    buffer[4]=0;
    buffer[5]=0;
    writebuff(buffer,6,7,36,2);

    buffer[8]=(devid/10)%2;
    buffer[10]=0;
    if(buffer[8]==0)
        buffer[11]=0;
    else
        buffer[11]=devid%25;
    
    sprintf(&buffer[12],name.c_str());

    memcpy(forsend,buffer,44);
    pos+=44;
    
    

    return OK;

}

int sendrowinfo(const char*cdevid,int socket_desc,char * forsend,int&pos){
    char text[9]={0};
    text[0]=0x91;
    text[1]=13;
    text[2]=0;
    text[3]=9;
    text[4]=0;
    text[5]=0;
    text[6]=0;
    text[7]=1;
    text[8]=0;


    memcpy(forsend,text,9);
    pos+=9;
    
    
    return OK;
}

int sendttyinfo(const char*cdevid,int socket_desc,int devid,int min,int max,char * forsend,int&pos){
    char text[280]={0};
    text[0]=0x91;
    text[1]=9;
    text[2]=1;
    text[3]=24;
    text[4]=0;
    text[5]=0;
    text[6]=1;
    text[7]=16;

    int async;
    if((devid/10)%3==1)
        async=8;
    else if((devid/10)%3==2)
        async=16;
    else
        async=0;

    int total=rand()%(max-min)+min;
    int async_term_num=0;
    if(async==8){
        async_term_num=rand()%8+1;
    }
    else if(async==16){
        async_term_num=rand()%16+1;
    }
    for(int i=0;i<async_term_num;i++){
        int pos=rand()%async_term_num;
        if(!text[8+pos])
            text[8+pos]=1;
        else
            i--;
    }

    if(total<async_term_num)
        total=async_term_num;
    int ipterm_num=total-async_term_num;
    for(int i=0;i<ipterm_num;i++){
        int pos=rand()%254;
        if(!text[24+pos])
            text[24+pos]=1;
        else
            i--;
    }

    int num=rand()%(270-total)+total;
    writebuff(text,278,279,num,2);


    memcpy(forsend,text,280);
    pos+=280;
    

    
    return total;
}


int senddevsetinfo(const char*cdevid,int socket_desc,int num,
    int minscr,int maxscr,std::string ipadr,int port,char * forsend,int&pos){
    
    int scrnum=rand()%(maxscr-minscr)+minscr;

    char*text=new char[36+96*scrnum];
    text[0]=0x91;
    text[1]=10;
    writebuff(text,2,3,36+scrnum*96,2);
    writebuff(text,4,5,num,2);
    writebuff(text,6,7,28+scrnum*96,2);
    text[8]=num,text[9]=num;

    int activate=rand()%scrnum;
    text[10]=activate;
    text[11]=scrnum;

    writebuff(text,12,15,0,4);
    sprintf(&text[16],"%s","串口终端");

    if(rand()%2)
        sprintf(&text[28],"%s","正常");
    else
        sprintf(&text[28],"%s","菜单");

    for(int i=0;i<scrnum;i++){
        int code=i+1;
        text[36+i*96]=code;
        writebuff(text,36+i*96+2,36+i*96+3,port,2);
        
        char ip[20]={0};
        sprintf(ip,"%s",ipadr.c_str());
        int temp=0;
        for(int pos=0,j=0;;pos++){
            temp*=10;
            if(ip[pos]=='.'||ip[pos]=='\0'){
                text[36+i*96+4+j]=temp;
                temp=0;
                j++;
            }
            else
                temp+=ip[pos]-'0';
            if(ip[pos]=='\0')
                break;
        }
        if(code%2)
            sprintf(&text[36+i*96+8],"%s","SSH");
        else
            sprintf(&text[36+i*96+8],"%s","专用SSH");

        if(code%9==0||code%9==3||code%9==6)
            sprintf(&text[36+i*96+20],"%s","开机");
        else if(code%9==1||code%9==4||code%9==7)
            sprintf(&text[36+i*96+20],"%s","关机");
        else
            sprintf(&text[36+i*96+20],"%s","已登录");
        
        if(code%9==0||code%9==1||code%9==2)
            sprintf(&text[36+i*96+28],"%s","储蓄系统");
        else if(code%9==3||code%9==4||code%9==5)
            sprintf(&text[36+i*96+28],"%s","基金开户");
        else
            sprintf(&text[36+i*96+28],"%s","中转业务");
        
        if(code%2)
            sprintf(&text[36+i*96+52],"%s","vt100");
        else
            sprintf(&text[36+i*96+52],"%s","vt220");

        writebuff(text,32+i*96+64,32+i*96+67,(unsigned int)(time(0)),4);
        writebuff(text,32+i*96+68,32+i*96+71,rand(),4);
        writebuff(text,32+i*96+72,32+i*96+75,rand(),4);
        writebuff(text,32+i*96+76,32+i*96+79,rand(),4);
        writebuff(text,32+i*96+80,32+i*96+83,rand(),4);

        
        writebuff(text,32+i*96+84,32+i*96+87,rand()%123457,4);
        writebuff(text,32+i*96+88,32+i*96+91,rand()%123457,4);
        writebuff(text,32+i*96+92,32+i*96+95,rand()%123457,4);

    }


    memcpy(forsend,text,36+96*scrnum);
    pos+=36+96*scrnum;
    


    delete[]text;
    return scrnum;
}

int sendipsetinfo(const char*cdevid,int socket_desc,int num,
    int minscr,int maxscr,std::string ipadr,int port,char * forsend,int&pos){
    
    int scrnum=rand()%(maxscr-minscr)+minscr;

    char*text=new char[36+96*scrnum];
    text[0]=0x91;
    text[1]=11;
    writebuff(text,2,3,36+scrnum*96,2);
    writebuff(text,4,5,num,2);
    writebuff(text,6,7,28+scrnum*96,2);
    text[8]=num,text[9]=num;

    int activate=rand()%scrnum;
    text[10]=activate;
    text[11]=scrnum;

    text[12]=rand()%255+1;
    text[13]=rand()%255+1;
    text[14]=rand()%255+1;
    text[15]=rand()%255+1;

    if(rand()%2)
        sprintf(&text[16],"%s","IP终端");
    else
        sprintf(&text[16],"%s","IP代理");

    if(rand()%2)
        sprintf(&text[28],"%s","正常");
    else
        sprintf(&text[28],"%s","菜单");

    for(int i=0;i<scrnum;i++){
        int code=i+1;
        text[36+i*96]=code;
        writebuff(text,36+i*96+2,36+i*96+3,port,2);
        
        char ip[20]={0};
        sprintf(ip,"%s",ipadr.c_str());
        int temp=0;
        for(int pos=0,j=0;;pos++){
            temp*=10;
            if(ip[pos]=='.'||ip[pos]=='\0'){
                text[36+i*96+4+j]=temp;
                temp=0;
                j++;
            }
            else
                temp+=ip[pos]-'0';
            if(ip[pos]=='\0')
                break;
        }
        if(code%2)
            sprintf(&text[36+i*96+8],"%s","SSH");
        else
            sprintf(&text[36+i*96+8],"%s","专用SSH");

        if(code%9==0||code%9==3||code%9==6)
            sprintf(&text[36+i*96+20],"%s","开机");
        else if(code%9==1||code%9==4||code%9==7)
            sprintf(&text[36+i*96+20],"%s","关机");
        else
            sprintf(&text[36+i*96+20],"%s","已登录");
        
        if(code%9==0||code%9==1||code%9==2)
            sprintf(&text[36+i*96+28],"%s","储蓄系统");
        else if(code%9==3||code%9==4||code%9==5)
            sprintf(&text[36+i*96+28],"%s","基金开户");
        else
            sprintf(&text[36+i*96+28],"%s","中转业务");
        
        if(code%2)
            sprintf(&text[36+i*96+52],"%s","vt100");
        else
            sprintf(&text[36+i*96+52],"%s","vt220");

        writebuff(text,36+i*96+64,36+i*96+67,(unsigned int)(time(0)),4);
        writebuff(text,36+i*96+68,36+i*96+71,rand(),4);
        writebuff(text,36+i*96+72,36+i*96+75,rand(),4);
        writebuff(text,36+i*96+76,36+i*96+79,rand(),4);
        writebuff(text,36+i*96+80,36+i*96+83,rand(),4);

        writebuff(text,36+i*96+84,36+i*96+87,rand()%123457,4);
        writebuff(text,36+i*96+88,36+i*96+91,rand()%123457,4);
        writebuff(text,36+i*96+92,36+i*96+95,rand()%123457,4);
    }


    
    memcpy(forsend,text,36+96*scrnum);
    pos+=36+96*scrnum;
    delete[]text;
    return scrnum;
}

int sendfinish(const char*cdevid,int socket_desc,char * forsend,int&pos){
    char text[8]={0};
    text[0]=0x91;
    text[1]=0xff;
    text[2]=0;
    text[3]=8;
    text[4]=0;
    text[5]=0;
    text[6]=0;
    text[7]=0;


    memcpy(forsend,text,8);
    pos+=8;
    
    
    return OK;

}