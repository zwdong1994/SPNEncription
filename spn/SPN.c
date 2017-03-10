#include "stdio.h"
#include "stdlib.h"
#include "math.h"
#include "string.h"
#include "memory.h"
char w[64];//储存二进制的w
char x[1024];//存储任意长度的明文
char cipher_[1024];//存储密文
char y[2048];//存储16进制密文
char key[16];//储存长度为16的密钥
char key_binary[16][64];//储存二进制形式的密钥
int s[16]={3,14,13,1,2,15,11,8,4,10,6,12,5,9,0,7};
int p[64]={1,9,17,25,33,41,49,57,
	       2,10,18,26,34,42,50,58,
		   3,11,19,27,35,43,51,59,
		   4,12,20,28,36,44,52,60,
		   5,13,21,29,37,45,53,61,
		   6,14,22,30,38,46,54,62,
		   7,15,23,31,39,47,55,63,
		   8,16,24,32,40,48,56,64};
void Bytes2Bits(char *srcBytes, char* dstBits,unsigned int sizeBits);//将bytes转换为bits
void Bits2Bytes(char *dstBytes, char* srcBits,unsigned int sizeBits); //将bits转换为bytes
void Bits2Hex(char *dstHex, char* srcBits,unsigned int sizeBits);//将bits转换为16进制
void Hex2Bits(char *srcHex, char* dstBits,unsigned int sizeBits);//将16进制转换为bits
void creatkey();
void XOR(char *num1,char *num2,char *result,int length);
void sbox(char *u,char *v);
void pbox(char *v,char *_w);
void encryptspn(char *plaintext,int length);
void decryptspn(char *ciphertext,int length);
int checkkey();
void creatrandomnum();
void main() 
{                                                           
	int i=0,length=0;
	char ch;
	char cipherinhex[2048]={0};
	char cipherinbits[8192]={0};
	char cipherinbytes[1024]={0};
	memset(key,0,16);
	for(i=0;i<16;i++)
	{
		memset(key_binary[i],0,64);
	}
	printf("请输入密钥（长度为16）:\n");
	scanf("%s",key);
	while(!checkkey())
	{
		printf("请重新输入密钥（长度为16）:\n");
	    scanf("%s",key);
	}
	creatkey();
	printf("请输入明文：");
	scanf("%s",x);
	length=strlen(x);
	encryptspn(x,length);
	length = length % 8 == 0 ? length : ((length >> 3 ) + 1)  << 3;
	Bytes2Bits(cipher_,cipherinbits,length<<3);
	Bits2Hex(y,cipherinbits,length<<3);
	y[length<<1]=0;
	printf("加密成功！\n");
	printf("密文为：%s\n",y);
	memset(key,0,16);
	printf("解密过程：\n请输入密钥（长度为16）:");
	scanf("%s",key);
	while(!checkkey())
	{
		printf("请输入密钥（长度为16）:");
		scanf("%s",key);
	}
	creatkey();
	printf("请输入密文：\n");
	scanf("%s",cipherinhex);
	length=strlen(cipherinhex);
	Hex2Bits(cipherinhex,cipherinbits,length<<2);
	decryptspn(cipherinbits,length>>1);
	printf("得到的明文为：\n%s\n",x);
	printf("生成中...");
		creatrandomnum();

	
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
	char _16key[128];
	Bytes2Bits(key,_16key,128);
	for(;i<=15;i++)
	{
		memcpy(key_binary[i],(_16key+i*4+1),64);
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
	for(;i<16;i++)
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
	for(;i<64;i++)
	{
		_w[i]=v[p[i]-1];
	}
}

void encryptspn(char *plaintext,int length)
{
	int num=0,i=0,j;
	char _8bytes[8]={0};
	char _hex[16]={0};
	char _u[64]={0},_v[64]={0},_y[64]={0};
	char _little8bytes[8]={0};
	char keyn[64];
	if(length%8==0)
	{
		num=length/8;
		for(;i<num;i++)
		{
			memcpy(_8bytes,plaintext+(i<<3),8);
			Bytes2Bits(_8bytes,w,64);
			for(j=0;j<14;j++)
			{
				memcpy(keyn,&key_binary[j][0],64);
				XOR(w,keyn,_u,64);
				sbox(_u,_v);
				pbox(_v,w);
			}
			XOR(w,&key_binary[14][0],_u,64);
			sbox(_u,_v);
			XOR(&key_binary[15][0],_v,_y,64);
			Bits2Bytes(cipher_+i*8,_y,64);
		}
		cipher_[length]='\0';
	}
	else if(length<8)
	{
		memcpy(_little8bytes,plaintext,length);
		Bytes2Bits(_little8bytes,w,64);
		for(j=0;j<14;j++)
		{
			XOR(w,key_binary[j],_u,64);
			sbox(_u,_v);
			pbox(_v,w);
		}
		XOR(w,key_binary[j],_u,64);
		sbox(_u,_v);
		XOR(key_binary[15],_v,_y,64);
		Bits2Bytes(cipher_,_y,64);
		cipher_[8]='\0';
	}
	else if(length>8)
	{
		num=length/8;
		for(;i<num;i++)
		{
			memcpy(_8bytes,plaintext+8*i,8);
			Bytes2Bits(_8bytes,w,64);
			for(j=0;j<14;j++)
			{
				XOR(w,key_binary[j],_u,64);
				sbox(_u,_v);
				pbox(_v,w);
			}
			XOR(w,key_binary[j],_u,64);
			sbox(_u,_v);
			XOR(key_binary[15],_v,_y,64);
			Bits2Bytes(cipher_+i*8,_y,64);
		}
		
		num=length%8;
		memcpy(_little8bytes,plaintext+8*i,num);
		Bytes2Bits(_little8bytes,w,64);
		for(j=0;j<14;j++)
		{
			XOR(w,key_binary[j],_u,64);
			sbox(_u,_v);
			pbox(_v,w);
		}
		XOR(w,key_binary[j],_u,64);
		sbox(_u,_v);
		XOR(key_binary[15],_v,_y,64);
		Bits2Bytes(cipher_+i*8,_y,64);
		cipher_[((length>>3)+1)<<3]='\0';
	}
}

void decryptspn(char *ciphertext,int length)
{
	int num=0,i,j;
	char _x[1024];
	char _64bits[64]={0};
	char _u[64]={0},_v[64]={0};
	char mid8byte[8]={0};
	char midbits[64]={0};
	memset(w,0,64);
	if(length%8==0)
	{
		num=length/8;
		for(i=0;i<num;i++)
		{
			memcpy(w,ciphertext+i*64,64);
		    XOR(w,&(key_binary[15][0]),_v,64);
		    sbox(_v,_u);
			XOR(_u,&(key_binary[14][0]),w,64);
			for(j=13;j>=0;j--)
			{
				pbox(w,_v);
				sbox(_v,_u);
				XOR(&(key_binary[j][0]),_u,w,64);
			}
			Bits2Bytes(mid8byte,w,64);
			memcpy(_x+8*i,mid8byte,8);
		}
		_x[length]='\0';
	}
	else if(length>8)
	{
		num=length/8;
		for(i=0;i<num;i++)
		{
			memcpy(w,ciphertext+i*64,64);
		    XOR(w,key_binary[15],_v,64);
		    sbox(_v,_u);
			XOR(_u,key_binary[14],w,64);
			for(j=13;j>=0;j--)
			{
				pbox(w,_v);
				sbox(_v,_u);
				XOR(key_binary[j],_u,w,64);
			}
			Bits2Bytes(mid8byte,w,64);
			memcpy(_x+8*i,mid8byte,8);
		}
		num=length%8;
		
		memcpy(midbits,ciphertext+i*64,num*8);
		memcpy(w,midbits,64);
		XOR(w,key_binary[15],_v,64);
		sbox(_v,_u);
		XOR(_u,key_binary[14],w,64);
		for(j=13;j>=0;j--)
		{
			pbox(w,_v);
			sbox(_v,_u);
			XOR(key_binary[j],_u,w,64);
		}
		Bits2Bytes(mid8byte,w,64);
		memcpy(_x+8*i,mid8byte,8);
		_x[length]='\0';
	}
	else if(length<8)
	{
		char midbits[64]={0};
		memcpy(midbits,ciphertext,length*8);
		memcpy(w,midbits,64);
		XOR(w,key_binary[15],_v,64);
		sbox(_v,_u);
		XOR(_u,key_binary[14],w,64);
		for(j=13;j>=0;j--)
		{
			pbox(w,_v);
			sbox(_v,_u);
			XOR(key_binary[j],_u,w,64);
		}
		Bits2Bytes(mid8byte,w,64);
		memcpy(_x,mid8byte,8);
		_x[length]='\0';
	}
	i=strlen(x);
	if(i!=length)
		memcpy(x,_x,i);
}
int checkkey()
{
	int length;
	length=strlen(key);
	if(length==16)
		return 1;
	else 
		return 0;
}
void creatrandomnum()
{
	FILE *IN,*OUT;
    int temp;
    char p,filein[8]={0};
    if((IN=fopen("D:\\learning\\密码学课设\\10.dat","rb"))==NULL)
    exit(-1);
    if((OUT=fopen("D:\\learning\\密码学课设\\10SPN.dat","wb"))==NULL)
    exit(-1);
	while(!feof(IN))
	{
		for(temp=0;temp<=7;temp++)
        {
            if(!feof(IN))
            filein[temp]=getc(IN);
        }
		encryptspn(filein,8);
		for(temp=0;temp<=7;temp++)
        {
            fputc(cipher_[temp],OUT);
        }
	}
	fclose(OUT);
    fclose(IN);
}