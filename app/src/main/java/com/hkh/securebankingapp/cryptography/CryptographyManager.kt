package com.hkh.securebankingapp.cryptography

import javax.crypto.Cipher

// Interface for managing cryptography operations

interface CryptographyManager {

    // Function to get an initialized Cipher for encryption
    fun getInitializedCipherForEncryption(): Cipher?

    // Function to get an initialized Cipher for decryption with a provided initialization vector
    fun getInitializedCipherForDecryption(initializationVector: ByteArray?): Cipher?

    // Function to encrypt plaintext using the provided Cipher
    fun encryptData(plaintext: String, cipher: Cipher?): ByteArray?

    // Function to decrypt ciphered bytes using the provided Cipher and return the plaintext
    fun decryptData(cipheredBytes: ByteArray, cipher: Cipher?): String?

}