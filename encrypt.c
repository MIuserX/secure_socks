#include <Python.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/aes.h>


int kk_encrypt(unsigned char *plaintext,
                int plaintext_len,	
		unsigned char *key,
		unsigned char *iv, 
		unsigned char *ciphertext)
{
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;

    ctx = EVP_CIPHER_CTX_new();

    EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv);
    EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);
    ciphertext_len = len;
    EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    
    return ciphertext_len;
}


//解密
int kk_decrypt(unsigned char *ciphertext, 
		int ciphertext_len, 
		unsigned char *key,
		unsigned char *iv, 
		unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;
    
    ctx = EVP_CIPHER_CTX_new();
    
    EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv);
    EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len);
    plaintext_len = len;
    
    EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
    plaintext_len += len;
    
    EVP_CIPHER_CTX_free(ctx);
    
    return plaintext_len;
}


static PyObject *MyEncrypt_encrypt(PyObject *self, PyObject * args) {
    int res;
    unsigned char key[32] = {8};
    unsigned char iv[16] = {6};
    char *src_buff;  // 源字符串指针
    int src_len = 0; // 源字符串长度
    unsigned char encrypt_buff[4096] = {0};
    int encrypt_len = 0;

    res = PyArg_ParseTuple(args, "s#", &src_buff, &src_len);
    if (!res) {
        Py_RETURN_NONE;
    }

    encrypt_len = kk_encrypt((unsigned char *)src_buff, src_len, key, iv, encrypt_buff);
    return (PyObject *)Py_BuildValue("s#", encrypt_buff, encrypt_len);
}


static PyObject *MyEncrypt_decrypt(PyObject *self, PyObject * args) {
    int res;
    unsigned char key[32] = {8};
    unsigned char iv[16] = {6};
    char *src_buff;
    int src_len = 0;
    unsigned char decrypt_buff[4096] = {0};
    int decrypt_len = 0;

    res = PyArg_ParseTuple(args, "s#", &src_buff, &src_len);
    if (!res) {
        Py_RETURN_NONE; //包装函数返回NULL，会在Python调用中产生一个TypeError的异常
    }

    decrypt_len = kk_decrypt((unsigned char *)src_buff, src_len, key, iv, decrypt_buff);
    return (PyObject *)Py_BuildValue("s#", decrypt_buff, decrypt_len);
}


// Module method table
static PyMethodDef MyEncryptMethods[] = {
    {"encrypt", MyEncrypt_encrypt, METH_VARARGS, "encrypt data"},
    {"decrypt", MyEncrypt_decrypt, METH_VARARGS, "decrypt data"},
    {NULL, NULL, 0, NULL}
};


// module structure
static struct PyModuleDef MyEncryptModule = {
    PyModuleDef_HEAD_INIT,
    "MyEncrypt",
    "a sample encryption tools",
    -1,
    MyEncryptMethods
};


PyMODINIT_FUNC PyInit_MyEncrypt(void)
{
    return PyModule_Create(&MyEncryptModule);
};


//int main(int argc, char **argv) {
//    unsigned char key[32] = {8};
//    unsigned char iv[16] = {6};
//    unsigned char *plaintext = (unsigned char *)"This is Test Plain Data,This is Test Plain Data.";
//    unsigned char encrypted_buff[1024];
//    unsigned char decrypted_buff[1024];
//    int decrypted_len;
//    int encrypted_len;
//
//    printf("source is: \n%s\n", plaintext);
//    printf("source len is: \n%ld\n", strlen((char *)plaintext));
//
//    //加密
//    encrypted_len = kk_encrypt(plaintext, key, iv, encrypted_buff);
//    printf("encrypted_len=%d\n", encrypted_len);
//
//    //解密
//    decrypted_len = kk_decrypt(encrypted_buff, encrypted_len, key, iv, decrypted_buff);
//    printf("decrypted_len=%d\n", decrypted_len);
//
//    decrypted_buff[decrypted_len] = '\0';
//
//    printf("Decrypted text is:\n");
//    printf("%s\n", decrypted_buff);
//
//    return 0;
//}
