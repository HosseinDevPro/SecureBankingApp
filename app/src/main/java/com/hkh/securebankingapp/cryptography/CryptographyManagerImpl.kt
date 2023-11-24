package com.hkh.securebankingapp.cryptography

import com.hkh.securebankingapp.utils.KeyStoreManager
import com.hkh.securebankingapp.utils.SecurityConstant.AES_GCM_NOPADDING
import com.hkh.securebankingapp.utils.SecurityConstant.AUTHENTICATION_TAG_SIZE
import com.hkh.securebankingapp.utils.SecurityConstant.KEY_ALIAS_SYMMETRIC
import java.nio.charset.StandardCharsets
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec

// Implementation of CryptographyManager interface for handling cryptographic operations

class CryptographyManagerImpl(
    private val keyStoreManager: KeyStoreManager // Constructor parameter for KeyStoreManager
) : CryptographyManager {

    // Function to get an initialized Cipher for encryption
    override fun getInitializedCipherForEncryption(): Cipher? {
        return try {
            val cipher = getRawCipher() // Getting a raw Cipher instance
            val secretKey = keyStoreManager.getKeyWithAlias(KEY_ALIAS_SYMMETRIC) // Getting secret key from KeyStoreManager
            cipher.init(Cipher.ENCRYPT_MODE, secretKey) // Initializing the cipher for encryption mode
            cipher // Returning the initialized cipher
        } catch (e: Exception) {
            e.printStackTrace()
            removeSecretKey() // In case of an exception, remove the secret key from the KeyStore
            null // Return null if an exception occurs
        }
    }

    // Function to get an initialized Cipher for decryption with a provided initialization vector
    override fun getInitializedCipherForDecryption(initializationVector: ByteArray?): Cipher? {
        return try {
            val cipher = getRawCipher() // Getting a raw Cipher instance
            val secretKey = keyStoreManager.getKeyWithAlias(KEY_ALIAS_SYMMETRIC) // Getting secret key from KeyStoreManager
            cipher.init(
                Cipher.DECRYPT_MODE,
                secretKey,
                GCMParameterSpec(AUTHENTICATION_TAG_SIZE, initializationVector) // Initializing the cipher for decryption mode with an initialization vector
            )
            cipher // Returning the initialized cipher
        } catch (e: Exception) {
            e.printStackTrace()
            removeSecretKey() // In case of an exception, remove the secret key from the KeyStore
            null // Return null if an exception occurs
        }
    }

    // Function to encrypt plaintext using the provided Cipher
    override fun encryptData(plaintext: String, cipher: Cipher?): ByteArray? {
        return try {
            val iv = cipher?.iv ?: ZERO_BYTES // Get IV from cipher or use zero bytes if null
            val cipheredBytes =
                cipher?.doFinal(plaintext.toByteArray(StandardCharsets.UTF_8)) ?: ZERO_BYTES // Encrypt plaintext to ciphered bytes
            iv + cipheredBytes // Concatenate IV and ciphered bytes
        } catch (e: Exception) {
            e.printStackTrace()
            null // Return null if an exception occurs during encryption
        }
    }

    // Function to decrypt ciphered bytes using the provided Cipher and return the plaintext
    override fun decryptData(cipheredBytes: ByteArray, cipher: Cipher?): String? {
        return try {
            val plaintext = cipher?.doFinal(cipheredBytes) ?: ZERO_BYTES // Decrypt ciphered bytes to plaintext
            String(plaintext, StandardCharsets.UTF_8) // Convert decrypted bytes to String
        } catch (e: Exception) {
            e.printStackTrace()
            null // Return null if an exception occurs during decryption
        }
    }

    // Function to get a raw Cipher instance with AES GCM NOPADDING
    private fun getRawCipher() = Cipher.getInstance(AES_GCM_NOPADDING)

    // Function to remove the secret key from the KeyStore
    private fun removeSecretKey() {
        keyStoreManager.removeKey(KEY_ALIAS_SYMMETRIC)
    }

    companion object {
        private val ZERO_BYTES = ByteArray(0) // Constant for zero bytes
    }
}