#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/conf.h>
#include <openssl/cmac.h>

#define BLOCK_SIZE 16


/* function prototypes */
void print_hex(unsigned char *, size_t);
void print_string(unsigned char *, size_t);
void usage(void);
void check_args(char *, char *, unsigned char *, int, int);
void keygen(unsigned char *, unsigned char *, unsigned char *, int);
int encrypt(unsigned char *, int, unsigned char *, unsigned char *,unsigned char *, int);
int decrypt(unsigned char *, int, unsigned char *, unsigned char *,unsigned char *, int);
int gen_cmac(unsigned char *, size_t, unsigned char *, unsigned char *, int);
int verify_cmac(unsigned char *, unsigned char *);
/*Extra functions*/
int read_file(char * input_file,unsigned char *plaintext);
void write_file(char *output_file, unsigned char * ciphertext,int ciphertext_length);
void get_encrypted_message (unsigned char * plaintext,int plaintext_len, unsigned char * chunk,int chunk_length, unsigned char * new_cmac,int new_cmac_length);
int concat(unsigned char *a,int cmac_length, unsigned char *b, int ciphertext_length, unsigned char * concat);
/* TODO Declare your function prototypes here... */

/*
 * Prints the hex value of the input
 * 16 values per line
 */
void print_hex(unsigned char *data, size_t len) {
    size_t i;

    if (!data)
        printf("NULL data\n");
    else {
        for (i = 0; i < len; i++) {
            if (!(i % 16) && (i != 0))
                printf("\n");
            printf("%02X ", data[i]);
        }
        printf("\n");
    }
}

/*
 * Prints the input as string
 */
void print_string(unsigned char *data, size_t len) {
    size_t i;

    if (!data)
        printf("NULL data\n");
    else {
        for (i = 0; i < len; i++)
            printf("%c", data[i]);
        printf("\n");
    }
}

/*Read file*/

int read_file(char * input_file,unsigned char *plaintext)
{

    int size =0;
    FILE *fp = fopen(input_file,"rb"); 

    // Return if could not open file 
    if (fp == NULL){
      return 0; 
  }
  
  do
  { 
        // Taking input single character at a time 
    plaintext[size] = fgetc(fp); 

        // Checking for end of file 
    if (feof(fp)){
        break ; 
    }
    size++;
    // printf("%c", plaintext[size]); 
}  while(1); 

fclose(fp); 
return size;

}


void write_file(char *output_file, unsigned char * ciphertext,int ciphertext_length){

    FILE * fpointer = fopen(output_file,"w");
    for (int i =0; i< ciphertext_length; i++){
       fputc(ciphertext[i],fpointer);
   }

   fclose(fpointer);

}
/**
 * Prints the usage message
 * Describe the usage of the new arguments you introduce
 **/
void usage(void) {
    printf(
        "\n"
        "Usage:\n"
        "    assign_1 -i in_file -o out_file -p passwd -b bits"
        " [-d | -e | -s | -v]\n"
        "    assign_1 -h\n"
        );
    printf(
        "\n"
        "Options:\n"
        " -i    path    Path to input file\n"
        " -o    path    Path to output file\n"
        " -p    psswd   Password for key generation\n"
        " -b    bits    Bit mode (128 or 256 only)\n"
        " -d            Decrypt input and store results to output\n"
        " -e            Encrypt input and store results to output\n"
        " -s            Encrypt+sign input and store results to output\n"
        " -v            Decrypt+verify input and store results to output\n"
        " -h            This help message\n"
        );
    exit(EXIT_FAILURE);
}

/**
 * Checks the validity of the arguments
 * Check the new arguments you introduce
 **/
void check_args(char *input_file, char *output_file, unsigned char *password,int bit_mode, int op_mode) {
    if (!input_file) {
        printf("Error: No input file!\n");
        usage();
    }

    if (!output_file) {
        printf("Error: No output file!\n");
        usage();
    }

    if (!password) {
        printf("Error: No user key!\n");
        usage();
    }

    if ((bit_mode != 128) && (bit_mode != 256)) {
        printf("Error: Bit Mode <%d> is invalid!\n", bit_mode);
        usage();
    }

    if (op_mode == -1) {
        printf("Error: No mode\n");
        usage();
    }
}

/**
 * Generates a key using a password
 **/
void keygen(unsigned char *password, unsigned char *key, unsigned char *iv,int bit_mode) {
    /* TODO Task A */

    // PKCS5_PBKDF2_HMAC_SHA1((const char *) password,strlen(( const char*)password),NULL, 0,1000,bit_mode,key);
    if(bit_mode == 16){
        EVP_BytesToKey(EVP_aes_128_ecb(),EVP_sha1(),NULL,password,strlen(( const char*)password),1,key,iv);
    }
    else if(bit_mode == 32){
        EVP_BytesToKey(EVP_aes_256_ecb(),EVP_sha1(),NULL,password,strlen(( const char*)password),1,key,iv);
    }
}


/**
 * Encrypts the data
 **/
int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,unsigned char *iv, unsigned char *ciphertext, int bit_mode) {

    // printf("Encryption: Plaintext length %d\n",plaintext_len );
    /* TODO Task B */
    EVP_CIPHER_CTX *ctx;

    int len;

    int ciphertext_len;


    /* Create and initialise the context */
    ctx = EVP_CIPHER_CTX_new();

    /*
     * Initialise the encryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    if(bit_mode == 16){
        EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, iv);
    }
    else if(bit_mode == 32){
        EVP_EncryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, key, iv);
    }

    /*
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);


    ciphertext_len = len;
    // printf("CipherLen: %d",ciphertext_len) ;/* Clean up */
    /*
     * Finalise the encryption. Further ciphertext bytes may be written at
     * this stage.
     */

    EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);

    ciphertext_len += len;
    // printf("CipherLen: %d",ciphertext_len) ;/* Clean up */


    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;



}

/**
 * Decrypts the data and returns the plaintext size
 **/
int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,unsigned char *iv, unsigned char *plaintext, int bit_mode) {

    /*TODO Task C */
    EVP_CIPHER_CTX *ctx;

    int len;

    int plaintext_len;

    /* Create and initialise the context */
    ctx = EVP_CIPHER_CTX_new();


    /*
     * Initialise the decryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    if(bit_mode == 16){
        EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, iv);
    }
    else if(bit_mode == 32){
        EVP_DecryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, key, iv);
    }
    /*
     * Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary.
     */
    EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len);

    plaintext_len = len;

    // printf("Decryption: Plaintext length: %d\n", strlen(plaintext));
    // printf("\n");

    /*
     * Finalise the decryption. Further plaintext bytes may be written at
     * this stage.
     */
    EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
    plaintext_len += len;
    // printf("Decryption plaintext length: %ld\n",strlen((const char *)plaintext) );

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}


/**
 * Generates a CMAC
 **/
int concat(unsigned char *a,int cmac_length, unsigned char *b, int ciphertext_length, unsigned char * concat){
    int lena = cmac_length;
    int lenb = ciphertext_length;
    // unsigned char *concat = (unsigned char *)malloc(lena+lenb+1);
    // copy & concat (including string termination)
    memcpy(concat,a,lena);
    memcpy(concat+lena,b,lenb+1);  
    return lena +lenb;    

}

int gen_cmac(unsigned char *data, size_t data_len, unsigned char *key,unsigned char *cmac, int bit_mode) {
    /* TODO Task D */

  size_t mactlen;

  CMAC_CTX *ctx = CMAC_CTX_new();
  if(bit_mode == 16){
    CMAC_Init(ctx, key, 16, EVP_aes_128_ecb(), NULL);
}
else if (bit_mode == 32){

    CMAC_Init(ctx, key, 32, EVP_aes_256_ecb(), NULL);
}

  // printf("data length = %lu bytes (%lu bits)\n",sizeof(data), sizeof(data)*8);

CMAC_Update(ctx, data, sizeof(data));
CMAC_Final(ctx, cmac, &mactlen);

  // printBytes(cmac, mactlen);
  /* expected result T = 070a16b4 6b4d4144 f79bdd9d d04a287c */

CMAC_CTX_free(ctx);
return strlen((char *)(cmac));
}


/**
 * Verifies a CMAC
 **/



void get_encrypted_message (unsigned char * plaintext,int plaintext_len, unsigned char * chunk,int chunk_length, unsigned char * new_cmac,int new_cmac_length){


    int j=0;
    for(int i=0; i < plaintext_len;i++)
    {
        if(i <= plaintext_len-BLOCK_SIZE-1)
        {
            chunk[i] = plaintext[i];
            // printf("%d\n",i );
        }
        else if(i > plaintext_len-BLOCK_SIZE-1){
            new_cmac[j] = plaintext[i];
            j = j + 1;


            // printf("%d %d \n",j, i );
            // printf("%02X ", new_cmac[i]);

        }
    }


}
int verify_cmac(unsigned char *cmac1, unsigned char *cmac2) {
    int verify;
    verify = 0;
    /* TODO Task E */
    // printf("NEW CMAC\n");
    // printf("%ld\n",strlen((char *) cmac1) );
    // print_string(cmac1,strlen((char *) cmac1));
    // printf("OLD CMAC\n");
    // printf("%ld\n",strlen((char *) cmac2) );
    // print_string(cmac2,strlen((char *) cmac2));


    // comparing strings str1 and str2
    verify = strcmp((const char *)cmac1,(const char *)cmac2);
    if(verify == 0){
       printf("TRUE\n" );
   }else if(verify != 1){
       printf("FALSE\n" );
   }

   return verify;
}



/* TODO Develop your functions here... */



/**
 * Encrypts the input file and stores the ciphertext to the output file
 *
 * Decrypts the input file and stores the plaintext to the output file
 *
 * Encrypts and signs the input file and stores the ciphertext concatenated with
 * the CMAC to the output file
 *
 * Decrypts and verifies the input file and stores the plaintext to the output
 * file
 **/
int
main(int argc, char **argv) {
    int opt;            /* used for command line arguments */
    int bit_mode;            /* defines the key-size 128 or 256 */
    int op_mode;            /* operation mode */
    char *input_file;        /* path to the input file */
    char *output_file;        /* path to the output file */
    unsigned char *password;    /* the user defined password */

    /* Init arguments */
    input_file = NULL;
    output_file = NULL;
    password = NULL;
    bit_mode = -1;
    op_mode = -1;


    /*
     * Get arguments
     */
    while ((opt = getopt(argc, argv, "b:i:m:o:p:desvh:")) != -1) {
        switch (opt) {
            case 'b':
            bit_mode = atoi(optarg);
            break;
            case 'i':
            input_file = strdup(optarg);
            break;
            case 'o':
            output_file = strdup(optarg);
            break;
            case 'p':
            password = (unsigned char *) strdup(optarg);

            break;
            case 'd':
                /* if op_mode == 1 the tool decrypts */
            op_mode = 1;
            break;
            case 'e':
                /* if op_mode == 1 the tool encrypts */
            op_mode = 0;
            break;
            case 's':
                /* if op_mode == 1 the tool signs */
            op_mode = 2;
            break;
            case 'v':
                /* if op_mode == 1 the tool verifies */
            op_mode = 3;
            break;
            case 'h':
            default:
            usage();
        }
    }

    /* check arguments */
    // print_string(password,strlen((char*)password));
    check_args(input_file, output_file, password, bit_mode, op_mode);

    /* TODO Develop the logic of your tool here... */


    /* Initialize the library */




    /* Keygen from password */
    if(op_mode == 0)
    {
        // printf("Welcome to encryption tool\n");
        /*malloc the plaintext*/
        unsigned char *plaintext =(unsigned char *) malloc(sizeof(unsigned char) * 4096);
        /* Read input file containing plaintext and store to plaintext length*/
        int plaintext_len = read_file(input_file,plaintext);
        /*Print the plaintext in string*/
        // printf("Plaintext String:\n");
        // print_string(plaintext,plaintext_len);
        /*Print the length plaintext*/
        // printf("Plaintext length: %d\n", plaintext_len);

        /* New bit mode*/
        int bit_mode_new = bit_mode/8;
        /*malloc for key*/
        unsigned char *key;
        key = (unsigned char *) malloc(sizeof(unsigned char) * bit_mode_new);
        /*Call key gen*/
        keygen(password,key,NULL,bit_mode_new);

        /*Print key in String*/
        // printf("Key String:\n");
        // print_string(key, strlen((char *) key));
        /*Print key in Hex*/
        // printf("Key Hex:\n");
        // print_hex(key, strlen((char *) key));
        // printf("Key length: %ld\n", strlen((char*)key));
        
        /*Encryption*/
        /*malloc for cipher text*/
        unsigned char *ciphertext;
        ciphertext = (unsigned char *) malloc(sizeof(unsigned char) * plaintext_len+BLOCK_SIZE);
        /*Call encrypt*/
        int ciphertext_length = encrypt(plaintext,plaintext_len,key,NULL,ciphertext, bit_mode_new);
        /*Print ciphertext in string*/
        // printf("Ciphertext String:\n");
        // print_string(ciphertext,ciphertext_length);
        /*Print ciphertext in Hex*/
        // printf("Ciphertext Hex:\n");
        // print_hex(ciphertext,ciphertext_length);
        /*Print ciphertext size*/
        // printf("Cipher size: %d\n",ciphertext_length);

        /*Write output file containing the cipher/encrypted message */
        write_file(output_file,ciphertext,ciphertext_length);
        /* Free the three mallocs*/
        free(plaintext);
        free(key);
        free(ciphertext);
    }
    else if(op_mode == 1){
        // printf("Welcome to decryption tool\n");
        /*Read input file containing cipher/encrypted message */
        unsigned char *ciphertext =(unsigned char *) malloc(sizeof(unsigned char) * 4096);
        int ciphertext_len = read_file(input_file,ciphertext);
        /*Print the CIpher text in string*/
        // printf("Cipher String:\n");
        // print_string(ciphertext,ciphertext_len);
        /*Print the Cipher text in hex*/
        // printf("Cipher Hex:\n");
        // print_hex(ciphertext,ciphertext_len);
        /*Print Cipher size*/
        // printf("Cipher size: %d\n",ciphertext_len);
        /* New bit mode*/
        int bit_mode_new = bit_mode/8;
        /*Malloc for key*/
        unsigned char* key = (unsigned char *) malloc(sizeof( unsigned char) * bit_mode_new);
        keygen(password,key,NULL,bit_mode_new);
        /*Print key in string */
        // printf("Key String:\n");
        // print_string(key, strlen((char *) key));
        /*Print key in Hex*/
        // printf("Key Hex:\n");
        // print_hex(key, strlen((char *) key));
        /*Print key length*/
        // printf("Key length: %ld\n", strlen((char*)key));
        // /*Decryption*/
        /*Malloc plaintext */
        unsigned char *plaintext = malloc(sizeof(unsigned char) * ciphertext_len+BLOCK_SIZE);
        /*Call decrypt*/
        int plaintext_len = decrypt(ciphertext, ciphertext_len,key,NULL,plaintext,bit_mode_new);
        // plaintext[plaintext_len] = '\0';
        /*Print plaintext in string */
        // printf("Plaintext String:\n");
        // print_string(plaintext,plaintext_len);
        /*Pirnt plaintext in hex*/
        // printf("Plaintext Hex:\n");
        // print_hex(plaintext, plaintext_len);
        /*Print plaintext length*/
        // printf("Plaintext length %d\n",plaintext_len );
        /*write plaintext to output file*/
        write_file(output_file,plaintext,plaintext_len);
        free(ciphertext);
        free(key);
        free(plaintext);
        
    }
    else if(op_mode == 2){
        // printf("Welcome to Data Signing tool (CMAC)\n");
        /*malloc the plaintext*/
        unsigned char *data =(unsigned char *) malloc(sizeof(unsigned char) * 4096);
        /* Read input file containing plaintext and store to plaintext length*/
        int data_len = read_file(input_file,data);
        /*Print the plaintext in string*/
        // printf("Plaintext String:\n");
        // print_string(data,data_len);
        /*Print the length plaintext*/
        // printf("Plaintext length: %d\n", data_len);

        /* New bit mode*/
        int bit_mode_new = bit_mode/8;

        /*Key generation*/

        /*malloc for key*/
        unsigned char *key = (unsigned char *) malloc(sizeof(unsigned char) * bit_mode_new);
        /*Call key gen*/
        keygen(password,key,NULL,bit_mode_new);
        /*Print key in String*/
        // printf("Key String:\n");
        // print_string(key, strlen((char *) key));
        /*Print key in Hex*/
        // printf("Key Hex:\n");
        // print_hex(key, strlen((char *) key));
        /*Print key length*/
        // printf("Key length: %ld\n", strlen((char*)key));
        /*Mallloc cmac*/
        unsigned char *cmac = (unsigned char *) malloc(sizeof(unsigned char) * data_len+BLOCK_SIZE);
        /*Create cmac encrypted*/
        int cmac_length = gen_cmac(data,data_len,key,cmac,bit_mode_new);
        /*Print cmac in string*/
        // printf("Cmac String:\n");
        // print_string(cmac,cmac_length);
        /*Print cmac in Hex*/
        // printf("Cmac Hex:\n");
        // print_hex(cmac,cmac_length);
        /*Print cmac size*/
        // printf("Cmac size: %d\n",cmac_length);

        /*Encryption*/

        /*malloc for cipher text*/
        unsigned char *ciphertext;
        ciphertext = (unsigned char *) malloc(sizeof(unsigned char) * data_len+BLOCK_SIZE);
        /*Call encrypt*/
        int ciphertext_length = encrypt(data,data_len,key,NULL,ciphertext, bit_mode_new);
        /*Print ciphertext in string*/
        // printf("Ciphertext String:\n");
        // print_string(ciphertext,ciphertext_length);
        /*Print ciphertext in Hex*/
        // printf("Ciphertext Hex:\n");
        // print_hex(ciphertext,ciphertext_length);
        /*Print ciphertext size*/
        // printf("Cipher size: %d\n",ciphertext_length);

        /*Concatenation*/

        /*Malloc size for con*/
        unsigned char *con = (unsigned char *) malloc(sizeof(unsigned char) * (cmac_length+ciphertext_length));
        /*Call concat function*/

        int concat_lenth =  concat(ciphertext,ciphertext_length,cmac,cmac_length,con);
        /*Print ciphertext in string*/
        // printf("Concat String:\n");
        // print_string(con,concat_lenth);
        /*Print ciphertext in Hex*/
        // printf("Concat Hex:\n");
        // print_hex(con,concat_lenth);
        /*Print ciphertext size*/
        // printf("Concat size: %d\n",concat_lenth);
        /*write to file */
        write_file(output_file,con,concat_lenth);
        free(data);
        free(key);
        free(cmac);
        free(ciphertext);
        free(con);
    }
    else if(op_mode == 3){
       // printf("Welcome to Data Verification tool (CMAC)\n");
    /*malloc the plaintext*/
       unsigned char *data =(unsigned char *) malloc(sizeof(unsigned char) * 4096);
    /* Read input file containing plaintext and store to plaintext length*/
       int data_len = read_file(input_file,data);
    /*Print the plaintext in string*/
       // printf("Plaintext String:\n");
       // print_string(data,data_len);
       // print_hex(data,data_len);
    /*Print the length plaintext*/
       // printf("Plaintext length: %d\n", data_len);
    /* New bit mode*/
       int bit_mode_new = bit_mode/8;

        /*Malloc size for chunk*/
       int chunk_length = 0;
       int new_cmac_length = 0;
       unsigned char *chunk =NULL;
       unsigned char *new_cmac =NULL;


       chunk = (unsigned char *) malloc(sizeof(unsigned char) * (data_len - 16));
       chunk_length = data_len - 16;
       // printf("Chunk length: %d\n",chunk_length );
       new_cmac = (unsigned char *) malloc(sizeof(unsigned char) * (16));
       new_cmac_length = 16;

       get_encrypted_message(data,data_len,chunk,chunk_length,new_cmac,new_cmac_length);

        /*Print ciphertext in string*/
       // printf("Chunk String:\n");
       // print_string(chunk,chunk_length);
        /*Print ciphertext in Hex*/
       // printf("Chunk Hex:\n");
       // print_hex(chunk,chunk_length);
        /*Print ciphertext size*/
       // printf("Chunk size: %d\n",chunk_length);
        /*Print ciphertext in string*/
       // printf("Cmac String:\n");
       // print_string(new_cmac,new_cmac_length);
        /*Print ciphertext in Hex*/
       // printf("Cmac Hex:\n");
       // print_hex(new_cmac,new_cmac_length);
        /*Print ciphertext size*/
       // printf("Cmac size: %d\n",new_cmac_length);


    /*malloc for key*/
       unsigned char *key = (unsigned char *) malloc(sizeof(unsigned char) * bit_mode_new);
        /*Call key gen*/
       keygen(password,key,NULL,bit_mode_new);
        /*Print key in String*/
    // printf("Key String:\n");
    // print_string(key, strlen((char *) key));
        /*Print key in Hex*/
    // printf("Key Hex:\n");
    // print_hex(key, strlen((char *) key));
        /*Print key length*/
    // printf("Key length: %ld\n", strlen((char*)key));

       unsigned char *plaintext = malloc(sizeof(unsigned char) * chunk_length+BLOCK_SIZE);
       int plaintext_len =  decrypt(chunk,chunk_length,key,NULL,plaintext,bit_mode_new) ;
    /*Print plaintext in string */
       // printf("Plaintext String:\n");
       // print_string(plaintext,plaintext_len);
        /*Pirnt plaintext in hex*/
       // printf("Plaintext Hex:\n");
       // print_hex(plaintext, plaintext_len);
        /*Print plaintext length*/
       // printf("Plaintext length %d\n",plaintext_len);


       unsigned char *cmac = (unsigned char *) malloc(sizeof(unsigned char) * plaintext_len+BLOCK_SIZE+1);
        /*Create cmac encrypted*/
       gen_cmac(plaintext,plaintext_len,key,cmac,bit_mode_new);
        /*Print cmac in string*/
    // printf("Cmac String:\n");
       // print_string(cmac,cmac_length);
        /*Print cmac in Hex*/
    // printf("Cmac Hex:\n");
       // print_hex(cmac,cmac_length);
        /*Print cmac size*/
    // printf("Cmac size: %d\n",cmac_length);
       if(verify_cmac(cmac, new_cmac)==0){
        write_file(output_file,plaintext,plaintext_len);
       }


       free(data);
       free(chunk);
       free(key);
       free(new_cmac);
       free(plaintext);
       free(cmac);
   }

    /* Clean up */
   free(input_file);
   free(output_file);
   free(password);


    /* END */
   return 0;
}