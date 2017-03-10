#include "stdio.h"
#include "stdlib.h"
#include "math.h"
#include "string.h"
#include "memory.h"
char w[16];//储存二进制的w
char x[1024];//存储任意长度的明文
char _cipher[1024];//存储密文
char y[2048];//存储16进制密文
char key[8];//储存长度为16的密钥
char key_binary[5][16];//储存二进制形式的密钥
int s[16]={14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7};
int S1_Box[16]={14,3,4,8,1,12,10,15,7,13,9,6,11,2,0,5};
int p[64]={1,5,9,13,
           2,6,10,14,
           3,7,11,15,
		   4,8,12,16};
int x_wire[8];
void Bytes2Bits(char *srcBytes, char* dstBits,unsigned int sizeBits);//将bytes转换为bits
void Bits2Bytes(char *dstBytes, char* srcBits,unsigned int sizeBits); //将bits转换为bytes
void Bits2Hex(char *dstHex, char* srcBits,unsigned int sizeBits);//将bits转换为16进制
void Hex2Bits(char *srcHex, char* dstBits,unsigned int sizeBits);//将16进制转换为bits
void creatkey();
void XOR(char *num1,char *num2,char *result,int length);
void sbox(char *u,char *v);
void pbox(char *v,char *_w);
void encryptspn(char *plaintext,int length);
int checkkey();
void Rantext(int *Out,int *In);	//随机生成T个二进制明文
void SPN_Cha(int len);
void SPN_Wire(int len);
void TenToBit(int *Out,int *In,int num);
void BitToTen(int *Out,int *In,int num);
void main()
{
	int i,length;
	char cipherinhex[2048]={0};
	char cipherinbits[8192]={0};
	char cipherinbytes[1024]={0};
	memset(key,0,8);
	for(i=0;i<5;i++)
	{
		memset(key_binary[i],0,16);
	}
	printf("请输入密钥（长度为4）:\n");
	scanf("%s",key);
	while(!checkkey())
	{
		printf("请重新输入密钥（长度为4）:\n");
	    scanf("%s",key);
	}
	creatkey();
	printf("请输入明文：");
	scanf("%s",x);
	length=strlen(x);
	encryptspn(x,length);
	length=length%2==0?length:(length>>1+1)<<1;
	Bytes2Bits(_cipher,cipherinbits,length<<3);
	Bits2Hex(y,cipherinbits,length<<3);
	y[length<<1]=0;
	printf("加密成功！\n");
	printf("密文为：%s\n",y);
	printf("线性分析为:");
	SPN_Wire(8000);
	printf("\n点击继续差分分析：\n");
	getchar();
	SPN_Cha(8000);
	getchar();
	getchar();
}

void Bytes2Bits(char *srcBytes, char* dstBits,unsigned int sizeBits)
{
	int i=0;
	for(i=0; i < sizeBits; i++)
		dstBits[i] = ((srcBytes[i>>3]<<(i&7)) & 128)>>7;
}

void Bits2Bytes(char *dstBytes, char* srcBits,unsigned int sizeBits)
{
	int i=0;
	memset(dstBytes,0,sizeBits>>3);
	for(i=0; i < sizeBits; i++)
		dstBytes[i>>3] |= (srcBits[i] << (7 - (i & 7)));
}

void Bits2Hex(char *dstHex, char* srcBits,unsigned int sizeBits)
{
	int i=0,j=0;
	memset(dstHex,0,sizeBits>>2);
	for(i=0; i < sizeBits; i++) //convert to int 0-15
		dstHex[i>>2] += (srcBits[i] << (3 - (i & 3)));
	for(j=0;j < (sizeBits>>2);j++)
		dstHex[j] += dstHex[j] > 9 ? 55 : 48; //convert to char '0'-'F'
}


void Hex2Bits(char *srcHex, char* dstBits,unsigned int sizeBits)
{
	int i=0,j=0;
	memset(dstBits,0,sizeBits);
	for(i=0;i < (sizeBits>>2);i++)
	{
		srcHex[i] -= srcHex[i] > 64 ? 55 : 48; //convert to char int 0-15
	}
	for(j=0; j < sizeBits; j++)
		dstBits[j] = ((srcHex[j>>2]<<(j&3)) & 15) >> 3;

}

void creatkey()
{
	int i=0;
	char _16key[32];
	Bytes2Bits(key,_16key,32);
	for(;i<=15;i++)
	{
		memcpy(key_binary[i],(_16key+i*4),16);
	}
}

void XOR(char *num1,char *num2,char *result,int length)
{
	int i=0;
	for(i=0; i<length; i++)
	{
		result[i] = num1[i]^num2[i];
	}
}

void sbox(char *u,char *v)
{
	int mid=0,i=0;
	char midbit[4]={0};
	for(;i<4;i++)
	{
		memcpy(midbit,u+i*4,4);
		mid=(midbit[0])+(midbit[1])*2+(midbit[2])*4+(midbit[3])*8;
		mid=s[mid];
		midbit[0]=(char)(mid%2);
		midbit[1]=(char)(mid/2%2);
		midbit[2]=(char)(mid/2/2%2);
		midbit[3]=(char)(mid/2/2/2%2);
		memcpy(v+i*4,midbit,4);
	}
}

void pbox(char *v,char *_w)
{
	int i=0;
	for(;i<16;i++)
	{
		_w[i]=v[p[i]-1];
	}
}

int checkkey()
{
	int length;
	length=strlen(key);
	if(length==4)
		return 1;
	else
		return 0;
}

void encryptspn(char *plaintext,int length)
{
	int num=0,i=0,j;
	char _2bytes[2]={0};
	char _little2bytes[2]={0};
	char _u[16]={0},_v[16]={0},_y[16]={0};
	if(length%2==0)
	{
		num=length/2;
		for(;i<num;i++)
		{
			memcpy(_2bytes,plaintext+2*i,2);
			Bytes2Bits(_2bytes,w,16);
			for(j=0;j<3;j++)
			{
				XOR(w,key_binary[j],_u,16);
				sbox(_u,_v);
				pbox(_v,w);
			}
			XOR(w,&key_binary[3][0],_u,16);
			sbox(_u,_v);
			XOR(&key_binary[4][0],_v,_y,16);
			Bits2Bytes(_cipher+i*2,_y,16);
		}
		_cipher[length]='\0';
	}
	else if(length<2)
	{
		memcpy(_little2bytes,plaintext,length);
		Bytes2Bits(_little2bytes,w,16);
		for(j=0;j<3;j++)
		{
			XOR(w,key_binary[j],_u,16);
			sbox(_u,_v);
			pbox(_v,w);
		}
		XOR(w,key_binary[j],_u,16);
		sbox(_u,_v);
		XOR(key_binary[4],_v,_y,16);
		Bits2Bytes(_cipher,_y,16);
		_cipher[2]='\0';
	}
	else if(length>2)
	{
		num=length/8;
		for(;i<num;i++)
		{
			memcpy(_2bytes,plaintext+2*i,2);
			Bytes2Bits(_2bytes,w,16);
			for(j=0;j<3;j++)
			{
				XOR(w,key_binary[j],_u,16);
				sbox(_u,_v);
				pbox(_v,w);
			}
			XOR(w,key_binary[j],_u,16);
			sbox(_u,_v);
			XOR(key_binary[4],_v,_y,16);
			Bits2Bytes(_cipher+i*2,_y,16);
		}

		num=length%2;
		memcpy(_little2bytes,plaintext+2*i,num);
		Bytes2Bits(_little2bytes,w,16);
		for(j=0;j<3;j++)
		{
			XOR(w,key_binary[j],_u,16);
			sbox(_u,_v);
			pbox(_v,w);
		}
		XOR(w,key_binary[j],_u,16);
		sbox(_u,_v);
		XOR(key_binary[4],_v,_y,16);
		Bits2Bytes(_cipher+i*2,_y,16);
		_cipher[(length/2+1)<<1]='\0';
	}
}

void Rantext(int *Out,int *In)	//随机生成T个二进制明文
{
    int i,j;
	char in[16],out[16];
	char bytesin[2];
    i=rand()%65536;
    for(j=15;j>=0;j--)
    {
        In[j]=i%2;
        i/=2;
    }
	for(j=15;j>=0;j--)
	{
		in[j]=In[j];
	}
	Bits2Bytes(bytesin,in,16);
    encryptspn(bytesin,2);
	Bytes2Bits(_cipher,out,16);
	for(j=15;j>=0;j--)
	{
		Out[j]=out[j];
	}
}

void SPN_Wire(int len)
{
    int L1,l1,L2,l2,z;
	int max=-1;
    int key1,key2;
    int i,j,m;
    int Key_Out[8]={0};
    int count[16][16];
    int RanIn[16]={0};
    int RanOut[16]={0};
    int U2[4]={0},U4[4]={0};
    for(L1=0;L1<16;L1++)
        for(L2=0;L2<16;L2++)
        count[L1][L2]=0;
    for(m=0;m<len;m++)
    {
        Rantext(RanOut,RanIn);
        for(L1=0;L1<16;L1++)
            for(L2=0;L2<16;L2++)
            {
                l1=L1^(RanOut[4]*8+RanOut[5]*4+RanOut[6]*2+RanOut[7]);
                l2=L2^(RanOut[12]*8+RanOut[13]*4+RanOut[14]*2+RanOut[15]);
                i=S1_Box[l1];
                TenToBit(U2,&i,4);
                j=S1_Box[l2];
                TenToBit(U4,&j,4);
                z=RanIn[4]^RanIn[6]^RanIn[7]^U2[1]^U2[3]^U4[1]^U4[3];
                if(z==0)
                   count[L1][L2]++;
             }
    }

    for(L1=0;L1<16;L1++)
        for(L2=0;L2<16;L2++)
    {
        count[L1][L2]=abs(count[L1][L2]-len/2);
        if(count[L1][L2]>max)
        {
                max=count[L1][L2];
                key1=L1;
                key2=L2;
        }
    }
    TenToBit(Key_Out,&key1,4);
    TenToBit(&Key_Out[4],&key2,4);
    for(i=0;i<8;i++)
    {
        printf("%d",Key_Out[i]);
        x_wire[i]=Key_Out[i];
    }
}

void TenToBit(int *Out,int *In,int num)
{
    int i;
    for(i=num-1;i>=0;i--)
    {
        Out[i]=In[i/4]%2;
        In[i/4]/=2;
    }
}

void SPN_Cha(int len)
{
    int L1,l1,L2,l2,z;
	int max=-1;
    int key1,key2;
    int i,j,m,p,q,r,t;
    int x[16]={0,0,0,0,1,0,1,1,0,0,0,0,0,0,0,0};
    int Key_Out[8]={0};
    int count[16][16];
    int RanIn[16]={0},RanIn1[16]={0};
    int RanOut[16]={0},RanOut1[16]={0};
    int U2,U4,U2_1,U4_1;
	char randin1[16],randout1[16];
	char bytesin[2];
    for(L1=0;L1<16;L1++)
        for(L2=0;L2<16;L2++)
        count[L1][L2]=0;
    for(m=0;m<len;m++)
    {
        Rantext(RanOut,RanIn);
        for(i=0;i<16;i++)
          RanIn1[i]=RanIn[i]^x[i];
		for(j=15;j>=0;j--)
	    {
		   randin1[j]=RanIn1[j];
	    }
		Bits2Bytes(bytesin,randin1,16);
        encryptspn(bytesin,2);
		Bytes2Bits(_cipher,randout1,16);
	    for(j=15;j>=0;j--)
	    {
		    RanOut[j]=randout1[j];
	    }
        BitToTen(&p,RanOut,4);
        BitToTen(&q,&RanOut[8],4);
        BitToTen(&r,RanOut1,4);
        BitToTen(&t,&RanOut1[8],4);
        if(p==r&&q==t)
        {
          for(L1=0;L1<16;L1++)
            for(L2=0;L2<16;L2++)
            {
                l1=L1^(RanOut[4]*8+RanOut[5]*4+RanOut[6]*2+RanOut[7]);
                l2=L2^(RanOut[12]*8+RanOut[13]*4+RanOut[14]*2+RanOut[15]);
                U2=S1_Box[l1];
                U4=S1_Box[l2];
                l1=L1^(RanOut1[4]*8+RanOut1[5]*4+RanOut1[6]*2+RanOut1[7]);
                l2=L2^(RanOut1[12]*8+RanOut1[13]*4+RanOut1[14]*2+RanOut1[15]);
                U2_1=S1_Box[l1];
                U4_1=S1_Box[l2];
                i=U2^U2_1;j=U4^U4_1;
                if(i==6&&j==6)
                    count[L1][L2]++;
            }

        }

    }

    for(L1=0;L1<16;L1++)
        for(L2=0;L2<16;L2++)
        if(count[L1][L2]>max)
        {
                max=count[L1][L2];
                key1=L1;
                key2=L2;
        }
    TenToBit(Key_Out,&key1,4);
    TenToBit(&Key_Out[4],&key2,4);
    for(i=0;i<8;i++)
        printf("%d",x_wire[i]);

}
void BitToTen(int *Out,int *In,int num)
{
    int i;
    for(i=0;i<num/4;i++)
        Out[i]=8*In[4*i]+4*In[4*i+1]+2*In[4*i+2]+In[4*i+3];
}
