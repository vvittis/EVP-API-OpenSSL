# Assignment 2

_In the following ReadMe file it will be presented the pipelining and the thought process for solving each Task and the implemented functions._

**NOte**

## Task A
### Key Derivation Function (KDF)

#### Some worth mentioning points

1. Every variable in order to be initialized in C, it has to be binded with some space in the memory. So, we malloc every each one variable throughout our project.
2. The size of the key has to be the bit_mode divided by eight. This is because we want to work with bytes and not bits.
3. We have always free each one malloc for every variable.

#### Implementing already existed Functions

##### keygen

The purpose of this function is to produce a key based on a password. There is a one to one relation between key and password. The most important point for this function is that we use the EVP_BytesToKey function. The function requires for the EVP_CIPHER and the EVP_MD among other parameters. The EVP_CIPHER is the AES block cipher as determined from the exercise and the EVP_MD is the SHA1 cryptographic hash function. According to the desired key size we call EVP_aes_128_ecb for 128 bits key and respectively the EVP_aes_256_ecb for 256 bits key. The salt is not needed as the professor guided us.Finally, the default value for the iterations with which the algorithm will encrypt the key is 1. So we do implement our algorithm with not so much protection and we are a little vulnerable to attacks as our key is not well protected.


## Task B
### Data Encryption

#### Implementing already existed Functions

#### encrypt 

The purpose of this function is to encrypt a plaintext based on a given key and a bit mode.
In this function we basically use the API of evp. Firstly, we create the cipher content and then we initialize the context based on the bit mode and the key. As we said it has to be a one to one relation between key and password, and that's the point, the sender and the receiver have to have a common "secret" password that they share. The next step is to create the cipher text based on the newly initialized context and the plain text. Lastly, we free the context.

**Note: The already defined function which was given has changed from void to int**


#### Extra Implemented Functions

##### read_file(char * input_file,unsigned char * plaintext)
I implemented a read file function. This function returns the numbers of bytes it reads. It stores the content of the file inside the unsigned char * plaintext. The reading is performed with the fgetc.

#### write_file(write_file(output_file,ciphertext,ciphertext_length)
I implemented a write file function. This function just writes to a file, not something special. The reason why I pass the cipher text length is because the strlen is not a trusted function when we deal with unsigned char.


## Task C
### Data Decryption

#### Implementing already existed Functions

#### decrypt 
The purpose of this function is to decrypt a cipher text based on a given cipher text, a key and a bit mode.
In this function we basically use the API of evp. Firstly, we create the cipher content and then we initialize the context based on the bit mode and the key.Secondly, we create the plain text based on the newly initialized context and the cipher text. Lastly, we free the context.

#### Extra Implemented Functions
Same functions as Task B.


## Task D
### Data Signing (CMAC)

#### Some worth mentioning points
1. The Cmac generation is related with the the encryption cipher algorithm that we use. In this project, as we have mentioned before we use AES in Electronic Code Book (ECB), so we during initializing the CMAC context we make use AES.
2. We have always free each one malloc for every variable.

#### Implementing already existed Functions

##### gen_mac 

The purpose of this function is to produce a CMAC (Cipher-based Message Authentication Code). The CMAC is basically a code that we use for extra protection in our messages. In the gen_mac function we firstly initialize the CMAC context which is essential for the initialization and the update of the CMAC. With the CMAC_final function we create the CMAC.  

**Note: The already defined function which was given has changed from void to int**

#### Extra Implemented Functions
Same functions as Task B plus concat.
##### concat 

This function is a simple function for concatenating two string, nothing special.

## Task E

### Data Verification (CMAC)
#### Some worth mentioning points
1. None of hpy414_verifyme_.txt files have same CMACs.So both files output FALSE.

#### Implementing already existed Functions
##### verify_cmac
This function takes two unsigned char arrays and compare them with strcmp, nothing too special. The output of this function is whether or not the produced CMAC and the CMAC obtained from the received message are equal.
#### Extra Implemented Functions
Same functions as Task B plus get_encrypted_message.

##### get_encrypted_message

The purpose of this function is to split the encrypted message which is concatenated with the CMAC into two different splits. An important question is raised here. 
How we split a string into two without knowing where the separation point is?
The answer is easy and because it is easy we are vulnerable to cipher attacks.
The block size of CMAC is always 16 bytes. So, if we know that the last 16 bytes is the CMAC the remaining chunk is the encrypted message that we have to decrypt.

**Note: IN CASE OF FALSE VERIFICATION: This task despite the fact that receives an output file DOES NOT WRITE to any file**

## Task F

### Command lines for testing

1. ./assign_1 -i encryptme_256.txt -o decryptme_256.txt -p TUC2015030164 -b 256 -e

2. ./assign_1 -i hpy414_decryptme_128.txt -o hpy414_encryptme_128_DONE.txt -p hpy414 -b 128 -d

3. ./assign_1 -i signme_128.txt -o verifyme_128.txt -p TUC2015030164 -b 128 -s

4.
	1. ./assign_1 -i hpy414_verifyme_128.txt -o hpy414_verifyme_128_DONE.txt -p hpy414 -b 128 -v


	2. ./assign_1 -i hpy414_verifyme_256.txt -o hpy414_verifyme_256_DONE.txt -p hpy414 -b 256 -v

