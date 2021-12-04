#include <stdio.h>
#include<iostream>
#define BYTE unsigned char
using namespace std;

//double t;

int change =0;
 
void printBytes(BYTE b[], int len) {
  int i;
  for (i=0; i<len; i++)
    printf("%d ", b[i]);
  printf("\n");
}
 void printByteshex(BYTE b[], int len) {
  int i;
  for (i=0; i<len; i++)
  {
  	
  	printf("%02x ", b[i]);
  }
    
  printf("\n");
}
void printByteskey(BYTE b[],int len)
{
	int i;
	int countkey=0;
	for(i=0;i<len;i++)
	{
		if(i==0||i%16==0)
		{
			printf("key%d :",(i)/16);
		}
		printf("%02x ",b[i]);
	 	if((i+1)%16==0)
		{
			printf("\n");
		}
		
	}
}
/******************************************************************************/
 
BYTE AES_Sbox[] = {99,124,119,123,242,107,111,197,48,1,103,43,254,215,171,
  118,202,130,201,125,250,89,71,240,173,212,162,175,156,164,114,192,183,253,
  147,38,54,63,247,204,52,165,229,241,113,216,49,21,4,199,35,195,24,150,5,154,
  7,18,128,226,235,39,178,117,9,131,44,26,27,110,90,160,82,59,214,179,41,227,
  47,132,83,209,0,237,32,252,177,91,106,203,190,57,74,76,88,207,208,239,170,
  251,67,77,51,133,69,249,2,127,80,60,159,168,81,163,64,143,146,157,56,245,
  188,182,218,33,16,255,243,210,205,12,19,236,95,151,68,23,196,167,126,61,
  100,93,25,115,96,129,79,220,34,42,144,136,70,238,184,20,222,94,11,219,224,
  50,58,10,73,6,36,92,194,211,172,98,145,149,228,121,231,200,55,109,141,213,
  78,169,108,86,244,234,101,122,174,8,186,120,37,46,28,166,180,198,232,221,
  116,31,75,189,139,138,112,62,181,102,72,3,246,14,97,53,87,185,134,193,29,
  158,225,248,152,17,105,217,142,148,155,30,135,233,206,85,40,223,140,161,
  137,13,191,230,66,104,65,153,45,15,176,84,187,22};
 
BYTE AES_ShiftRowTab[] = {0,5,10,15,4,9,14,3,8,13,2,7,12,1,6,11};
 
BYTE AES_Sbox_Inv[256];
BYTE AES_ShiftRowTab_Inv[16];
BYTE AES_xtime[256];
 
void AES_SubBytes(BYTE state[], BYTE sbox[]) {
  int i;
  for(i = 0; i < 16; i++)
    state[i] = sbox[state[i]];
}
 
void AES_AddRoundKey(BYTE state[], BYTE rkey[]) {
  int i;
  for(i = 0; i < 16; i++)
    state[i] ^= rkey[i];
}
 
void AES_ShiftRows(BYTE state[], BYTE shifttab[]) {
  BYTE h[16];
  memcpy(h, state, 16);
  int i;
  for(i = 0; i < 16; i++)
    state[i] = h[shifttab[i]];
}
 
void AES_MixColumns(BYTE state[]) {
  int i;
  for(i = 0; i < 16; i += 4) {
    BYTE s0 = state[i + 0], s1 = state[i + 1];
    BYTE s2 = state[i + 2], s3 = state[i + 3];
    BYTE h = s0 ^ s1 ^ s2 ^ s3;
    state[i + 0] ^= h ^ AES_xtime[s0 ^ s1];
    state[i + 1] ^= h ^ AES_xtime[s1 ^ s2];
    state[i + 2] ^= h ^ AES_xtime[s2 ^ s3];
    state[i + 3] ^= h ^ AES_xtime[s3 ^ s0];
  }
}
 
void AES_MixColumns_Inv(BYTE state[]) {
  int i;
  for(i = 0; i < 16; i += 4) {
    BYTE s0 = state[i + 0], s1 = state[i + 1];
    BYTE s2 = state[i + 2], s3 = state[i + 3];
    BYTE h = s0 ^ s1 ^ s2 ^ s3;
    BYTE xh = AES_xtime[h];
    BYTE h1 = AES_xtime[AES_xtime[xh ^ s0 ^ s2]] ^ h;
    BYTE h2 = AES_xtime[AES_xtime[xh ^ s1 ^ s3]] ^ h;
    state[i + 0] ^= h1 ^ AES_xtime[s0 ^ s1];
    state[i + 1] ^= h2 ^ AES_xtime[s1 ^ s2];
    state[i + 2] ^= h1 ^ AES_xtime[s2 ^ s3];
    state[i + 3] ^= h2 ^ AES_xtime[s3 ^ s0];
    
  }
}
 
// AES_Init: initialize the tables needed at runtime. 
// Call this function before the (first) key expansion.
void AES_Init() {
  int i;
  for(i = 0; i < 256; i++)
    AES_Sbox_Inv[AES_Sbox[i]] = i;
   
  for(i = 0; i < 16; i++)
    AES_ShiftRowTab_Inv[AES_ShiftRowTab[i]] = i;
 
  for(i = 0; i < 128; i++) {//確認是否溢位 
    AES_xtime[i] = i << 1;
    AES_xtime[128 + i] = (i << 1) ^ 0x1b;
  }
}
 
// AES_Done: release memory reserved by AES_Init. 
// Call this function after the last encryption/decryption operation.
void AES_Done() {}
 
/* AES_ExpandKey: expand a cipher key. Depending on the desired encryption 
   strength of 128, 192 or 256 bits 'key' has to be a byte array of length 
   16, 24 or 32, respectively. The key expansion is done "in place", meaning 
   that the array 'key' is modified.
*/  
int AES_ExpandKey(BYTE key[], int keyLen) {
  int kl = keyLen, ks, Rcon = 1, i, j;
  BYTE temp[4], temp2[4];
  switch (kl) {
    case 16: ks = 16 * (10 + 1); break;
    case 24: ks = 16 * (12 + 1); break;
    case 32: ks = 16 * (14 + 1); break;
    case 48: ks = 16 * (18 + 1); break;
    case 64: ks = 16 * (22 + 1); break;
    default: 
      printf("AES_ExpandKey: Only key lengths of 16, 24, 32 ,48 or 64 bytes allowed!\n");
  }
  for(i = kl; i < ks; i += 4) {
    memcpy(temp, &key[i-4], 4);
    
    if (i % kl == 0) {
      temp2[0] = AES_Sbox[temp[1]] ^ Rcon;
      temp2[1] = AES_Sbox[temp[2]];
      temp2[2] = AES_Sbox[temp[3]];
      temp2[3] = AES_Sbox[temp[0]];
      memcpy(temp, temp2, 4);
      if ((Rcon <<= 1) >= 256)
        Rcon ^= 0x11b;
    }else if ((kl > 48) && (i % kl == 48)) {//mod 12 ==0
      temp2[0] = AES_Sbox[temp[0]];
      temp2[1] = AES_Sbox[temp[1]];
      temp2[2] = AES_Sbox[temp[2]];
      temp2[3] = AES_Sbox[temp[3]];
      memcpy(temp, temp2, 4);
    }
	
	else if ((kl > 32) && (i % kl == 32)) {//mod 8==0
      temp2[0] = AES_Sbox[temp[0]];
      temp2[1] = AES_Sbox[temp[1]];
      temp2[2] = AES_Sbox[temp[2]];
      temp2[3] = AES_Sbox[temp[3]];
      memcpy(temp, temp2, 4);
    }
    else if ((kl > 24) && (i % kl == 16)) {//mod 4==0
      temp2[0] = AES_Sbox[temp[0]];
      temp2[1] = AES_Sbox[temp[1]];
      temp2[2] = AES_Sbox[temp[2]];
      temp2[3] = AES_Sbox[temp[3]];
      memcpy(temp, temp2, 4);//-----------------------
    }
    for(j = 0; j < 4; j++)
      key[i + j] = key[i + j - kl] ^ temp[j];
  }
  return ks;//
}
 
// AES_Encrypt: encrypt the 16 byte array 'block' with the previously expanded key 'key'.
void AES_Encrypt(BYTE block[], BYTE key[], int keyLen) {
  int l = keyLen, i;
  int roun=0;
  printf("\n");
  /*第0個round的加密結果*/
  AES_AddRoundKey(block, &key[0]);
  printf("round %d: ",roun);
  roun++;
  for(int i=0;i<16;i++)
  {	
  		printf("%02x ",block[i]);		
		//if(i%4==0)printf("\n");
  }
  printf("\n");
  /*第1~n-1個round的加密結果*/
  for(i = 16; i < l - 16; i += 16) {
  		 
  	printf("round %d: ",roun);
  	roun++;
    AES_SubBytes(block, AES_Sbox);
    AES_ShiftRows(block, AES_ShiftRowTab);
    AES_MixColumns(block);
    AES_AddRoundKey(block, &key[i]);
    for(int i=0;i<16;i++)
    {
    	printf("%02x ",block[i]);
	}
	printf("\n");
  }
  /*第n個round的加密結果*/
  AES_SubBytes(block, AES_Sbox);
  AES_ShiftRows(block, AES_ShiftRowTab);
  AES_AddRoundKey(block, &key[i]);
  printf("round %d: ",roun);
  for(int i=0;i<16;i++)
  {
  	printf("%02x ",block[i]);
  }
  printf("\n \n");
}
 
// AES_Decrypt: decrypt the 16 byte array 'block' with the previously expanded key 'key'.
void AES_Decrypt(BYTE block[], BYTE key[], int keyLen) {
  int l = keyLen, i;
  AES_AddRoundKey(block, &key[l - 16]);
  AES_ShiftRows(block, AES_ShiftRowTab_Inv);
  AES_SubBytes(block, AES_Sbox_Inv);
  for(i = l - 32; i >= 16; i -= 16) {
    AES_AddRoundKey(block, &key[i]);
    AES_MixColumns_Inv(block);
    AES_ShiftRows(block, AES_ShiftRowTab_Inv);
    AES_SubBytes(block, AES_Sbox_Inv);
  }
  AES_AddRoundKey(block, &key[0]);
}
 void tobinary(BYTE block1, BYTE block2)
 {
 	BYTE binary1[8];
 	BYTE binary2[8];
 	for(int i=0;i<8;i++)
 	{		
 		if((block1>>i)&0x01==1)
 		{
 			binary1[7-i]=1;
		 }else{
		 	binary1[7-i]=0;
		 }
		 
		 if((block2>>i)&0x01==1)
 		{
 			binary2[7-i]=1;
		 }else{
		 	binary2[7-i]=0;
		 }
	 }
	 for(int i=0;i<8;i++)
	 {
	 	printf("%d",binary1[i]);
	 }
	 printf("\t");
	 for(int i=0;i<8;i++)
	 {
	 	printf("%d",binary2[i]);
	 }
	 for(int i=0;i<8;i++)
	 {
	 	if(binary1[i]!=binary2[i])
	 	{
	 		change++;
		 }
	 }
 }
// ===================== test ============================================
int main() {
  
  int r=10;

  int i;
  AES_Init();
     
  BYTE block1[16];
  BYTE block2[16];
  
  printf("請輸入明文一(16個字元)：");
  for(i = 0; i < 16; i++)
    //block1[i]= 0x01 * i;
    cin>>block1[i];
  //printf("\n"); 
  
  printf("請輸入明文二(16個字元)：");
  for(i = 0; i < 16; i++)
    //block2[i]= 0x02 * i;
    cin>>block2[i];
  printf("\n"); 
  
  change=0;

	
  printf("明文一(ASCII code)："); printByteshex(block1, 16);
  printf("明文二(ASCII code)："); printByteshex(block2, 16);
 
  
  int keybits;
  int keyLen;
  //int maxKeyLen=16 * (22 + 1), 
  int blockLen = 16;
  
  printf("\n"); 
  printf("請輸入金鑰長度(128 / 192 / 256 / 384 / 512 bit)：");
  cin>>keybits;
  //printf("%d",keybits);
  while(keybits!=128 && keybits!=192 && keybits!=256 && keybits!=384 && keybits!=512)
  {
  	printf("請輸入128 / 192 / 256 / 384 / 512 \n");
  	cin>>keybits;
  }
  
  keyLen=keybits/8;
  BYTE key1[16 * (22 + 1)]={0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c,
						   0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c,0x2b,
						   0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c,
						   0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c,0x2b};
  BYTE key[16 * (22 + 1)];
  for(int i=0;i<keyLen;i++)
  	key[i]=key1[i];			     

  int keyf=0;
  printf("請輸入金鑰(%d byte)：1.自行輸入 2. 使用預設金鑰\n",keyLen);
  cin>>keyf;
  while(keyf!=1 &&keyf!=2)
  {
  	printf("請輸入 1 或 2 \n");
  	cin>>keyf;
  }
  if(keyf==1)
  {
  	printf("請輸入金鑰\n");
    for(i = 0; i < keyLen; i++)
      cin>>key[i];  	
  }

    
 
  printf("原始金鑰(ASCII code)：\n"); printByteshex(key, keyLen);
  printf("\n");
  
  //begin=clock();//開始計時
   
  int expandKeyLen = AES_ExpandKey(key, keyLen);
  //printf("\nexpandkeylen = %d\n",expandKeyLen);
 
  printf("展開金鑰：\n"); printByteskey(key, expandKeyLen);
 
  printf("\n");
  printf("明文一加密過程：");AES_Encrypt(block1, key, expandKeyLen);
  printf("明文二加密過程：");AES_Encrypt(block2, key, expandKeyLen);
 
  printf("明文一加密完後："); printByteshex(block1, blockLen);
  printf("明文二加密完後："); printByteshex(block2, blockLen);
 //------雪崩效應-------- 
  for(int i=0;i<16;i++)
  {
  	tobinary(block1[i],block2[i]);

  	printf("\n");
  }
  
  
  printf("改變了%d個0和1",change);
  printf("\n");
  printf("變動率為%.1f \n",((float(change)/128)*100));
  
  AES_Decrypt(block1, key, expandKeyLen);
  AES_Decrypt(block2, key, expandKeyLen);
 
  printf("明文一解密完後："); printByteshex(block1, blockLen);
  printf("明文二解密完後："); printByteshex(block2, blockLen);

  AES_Done();
  
  //end=clock();//計時結束 
  //t = double(end-begin);
  //cout<<"執行時間:"<<t<<"ms"<<endl;
  printf("\n");
  system("pause");
  return 0;
}
