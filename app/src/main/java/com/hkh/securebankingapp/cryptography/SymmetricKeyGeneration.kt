package com.hkh.securebankingapp.cryptography

import android.os.Build
import android.security.KeyStoreException
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.util.Log
import com.hkh.securebankingapp.utils.HexUtils.hexToByteArray
import com.hkh.securebankingapp.utils.KeyStoreManager
import com.hkh.securebankingapp.utils.SecurityConstant.AES_GCM_NOPADDING
import com.hkh.securebankingapp.utils.SecurityConstant.ANDROID_KEY_STORE_PROVIDER
import com.hkh.securebankingapp.utils.SecurityConstant.APP_TAG
import com.hkh.securebankingapp.utils.SecurityConstant.AUTHENTICATION_TAG_SIZE
import com.hkh.securebankingapp.utils.SecurityConstant.KEY_ALIAS_SYMMETRIC
import com.hkh.securebankingapp.utils.SecurityConstant.KEY_SIZE
import com.hkh.securebankingapp.utils.SecurityConstant.AUTHENTICATION_VALIDITY_DURATION
import com.hkh.securebankingapp.utils.SecurityConstant.INITIAL_VECTOR_SIZE
import java.io.IOException
import java.nio.charset.StandardCharsets
import java.security.InvalidAlgorithmParameterException
import java.security.InvalidKeyException
import java.security.NoSuchAlgorithmException
import java.security.NoSuchProviderException
import java.security.UnrecoverableEntryException
import java.security.cert.CertificateException
import javax.crypto.BadPaddingException
import javax.crypto.Cipher
import javax.crypto.IllegalBlockSizeException
import javax.crypto.KeyGenerator
import javax.crypto.NoSuchPaddingException
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

class SymmetricKeyGeneration(private val keyStoreManager: KeyStoreManager) {

    // Create key if not exist, else retrieve the key from keystore
    fun getOrGenerateKey(): SecretKey? {
        // Check if the secret key with the specified alias exists in the keystore
        if (!keyStoreManager.isKeyExist(KEY_ALIAS_SYMMETRIC)) {
            // If the key doesn't exist, create and store a new secret key
            createAndStoreSecretKey()
        }
        // Retrieve the secret key with the specified alias from the keystore
        return keyStoreManager.getKeyWithAlias(KEY_ALIAS_SYMMETRIC)
    }

    private fun createAndStoreSecretKey(): SecretKey? {
        try {
            // Create a KeyGenerator instance for AES encryption using the Android Keystore provider
            val aesKeyGenerator: KeyGenerator =
                KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEY_STORE_PROVIDER)

            // Initialize the KeyGenerator with the specified parameters for key generation
            aesKeyGenerator.init(getKeyGenParameterSpec())

            // Generate and store the secret key securely in the Android Keystore
            return aesKeyGenerator.generateKey()
        } catch (e: NoSuchAlgorithmException) {
            // Handle exceptions for NoSuchAlgorithmException (e.g., if AES is not supported)
            Log.d(APP_TAG, e.stackTraceToString())
            return null
        } catch (e: NoSuchProviderException) {
            // Handle exceptions for NoSuchProviderException (e.g., if the Keystore provider is not available)
            Log.d(APP_TAG, e.stackTraceToString())
            return null
        } catch (e: InvalidAlgorithmParameterException) {
            // Handle exceptions for InvalidAlgorithmParameterException (e.g., invalid key generation parameters)
            Log.d(APP_TAG, e.stackTraceToString())
            return null
        } catch (e: KeyPermanentlyInvalidatedException) {
            // Handle exceptions for KeyPermanentlyInvalidatedException (e.g., key invalidated due to biometric changes)
            Log.d(APP_TAG, e.stackTraceToString())
            return null
        }
    }

    // Key main spec is AES / GCM / NoPadding
    private fun getKeyGenParameterSpec(): KeyGenParameterSpec {
        // Create a KeyGenParameterSpec.Builder for configuring key generation
        val builder: KeyGenParameterSpec.Builder = KeyGenParameterSpec.Builder(
            KEY_ALIAS_SYMMETRIC, // Specify the key alias for the generated key
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT // Specify the key's purposes
        ).apply {
            setKeySize(KEY_SIZE) // Set the key size (e.g., 256 bits)
            setBlockModes(KeyProperties.BLOCK_MODE_GCM) // Use GCM block mode for encryption
            setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE) // Specify no encryption padding
            setUserAuthenticationRequired(true) // Require user authentication to use the key
            setRandomizedEncryptionRequired(true) // Require randomized encryption for added security
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                // Set additional security feature for Android R (API level 30) and higher
                setUserAuthenticationParameters(
                    AUTHENTICATION_VALIDITY_DURATION,// The key will require strong biometric authentication and remain valid for 10 seconds
                    KeyProperties.AUTH_BIOMETRIC_STRONG// Set user authentication strong for a cryptographic key
                )
            } else {
                setUserAuthenticationValidityDurationSeconds(AUTHENTICATION_VALIDITY_DURATION) // Specify user authentication validity duration (in seconds)
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                // Set additional security feature for Android N (API level 24) and higher
                setInvalidatedByBiometricEnrollment(true) // Invalidate the key if biometric enrollment changes
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                // Set additional security features for Android P (API level 28) and higher
                setUnlockedDeviceRequired(true) // Require an unlocked device to use the key
                setIsStrongBoxBacked(true) // Use StrongBox security if available
            }
        }
        return builder.build() // Build and return the KeyGenParameterSpec
    }

    @Throws(KeyStoreException::class)
    // It got a plain text and return base64 encoded string of encrypted
    fun encrypt(plainText: String): ByteArray? {
        try {
            // Convert the plain text into a byte array using UTF-8 encoding
            val plainBytes = plainText.toByteArray(StandardCharsets.UTF_8)

            // Retrieve the secret key from the keystore using the specified alias
            val key = keyStoreManager.getKeyWithAlias(KEY_ALIAS_SYMMETRIC)

            // Create a Cipher instance for AES-GCM encryption
            val cipher = Cipher.getInstance(AES_GCM_NOPADDING)

            // Initialize the cipher for encryption using the retrieved key
            cipher.init(Cipher.ENCRYPT_MODE, key)

            // Obtain the IV (Initialization Vector) from the initialized cipher
            val iv = cipher.iv

            // Encrypt the plain text bytes using the cipher
            val encryptedBytes = cipher.doFinal(plainBytes)

            // Containing the IV bytes and the encrypted
            return iv + encryptedBytes
        } catch (e: UnrecoverableEntryException) {
            // Handle exceptions related to key retrieval and keystore operations
            Log.d(APP_TAG, e.stackTraceToString())
            return null
        } catch (e: NoSuchAlgorithmException) {
            // Handle exceptions related to unsupported algorithms
            Log.d(APP_TAG, e.stackTraceToString())
            return null
        } catch (e: CertificateException) {
            // Handle exceptions related to certificate issues
            Log.d(APP_TAG, e.stackTraceToString())
            return null
        } catch (e: IOException) {
            // Handle exceptions related to input/output issues
            Log.d(APP_TAG, e.stackTraceToString())
            return null
        } catch (e: NoSuchPaddingException) {
            // Handle exceptions related to unsupported padding
            Log.d(APP_TAG, e.stackTraceToString())
            return null
        } catch (e: InvalidKeyException) {
            // Handle exceptions related to invalid encryption key
            Log.d(APP_TAG, e.stackTraceToString())
            return null
        } catch (e: IllegalBlockSizeException) {
            // Handle exceptions related to illegal block sizes
            Log.d(APP_TAG, e.stackTraceToString())
            return null
        } catch (e: BadPaddingException) {
            // Handle exceptions related to bad padding
            Log.d(APP_TAG, e.stackTraceToString())
            return null
        } catch (e: IllegalArgumentException) {
            // Handle exceptions related to illegal argument
            Log.d(APP_TAG, e.stackTraceToString())
            return null
        }
    }

    @Throws(KeyStoreException::class)
    // It got a hex encoded string and return plain decrypted text
    fun decrypt(encryptedHexEncodedText: String): String? {
        try {
            // Decode the Hex-encoded iv and encrypted text into bytes
            val allBytes = encryptedHexEncodedText.hexToByteArray()

            // Extract iv 12 bytes
            val iv = allBytes.sliceArray(0 .. INITIAL_VECTOR_SIZE-1)

            // Extract all other ciphered bytes
            val encryptedBytes = allBytes.sliceArray(INITIAL_VECTOR_SIZE.. allBytes.lastIndex)

            // Retrieve the secret key from the keystore using the specified alias
            val key = keyStoreManager.getKeyWithAlias(KEY_ALIAS_SYMMETRIC)

            // Create a GCMParameterSpec with the authentication tag size and the provided IV
            val spec = GCMParameterSpec(AUTHENTICATION_TAG_SIZE, iv)

            // Create a Cipher instance for AES-GCM decryption
            val cipher = Cipher.getInstance(AES_GCM_NOPADDING)

            // Initialize the cipher for decryption using the key and GCM parameters
            cipher.init(Cipher.DECRYPT_MODE, key, spec)

            // Decrypt the encrypted bytes using the initialized cipher
            val decryptedBytes = cipher.doFinal(encryptedBytes)

            // Convert the decrypted bytes back to a string using UTF-8 encoding
            return String(decryptedBytes, StandardCharsets.UTF_8)
        } catch (e: UnrecoverableEntryException) {
            // Handle exceptions related to key retrieval and keystore operations
            Log.d(APP_TAG, e.stackTraceToString())
            return null
        } catch (e: NoSuchAlgorithmException) {
            // Handle exceptions related to unsupported algorithms
            Log.d(APP_TAG, e.stackTraceToString())
            return null
        } catch (e: CertificateException) {
            // Handle exceptions related to certificate issues
            Log.d(APP_TAG, e.stackTraceToString())
            return null
        } catch (e: IOException) {
            // Handle exceptions related to input/output issues
            Log.d(APP_TAG, e.stackTraceToString())
            return null
        } catch (e: NoSuchPaddingException) {
            // Handle exceptions related to unsupported padding
            Log.d(APP_TAG, e.stackTraceToString())
            return null
        } catch (e: InvalidKeyException) {
            // Handle exceptions related to an invalid encryption key
            Log.d(APP_TAG, e.stackTraceToString())
            return null
        } catch (e: IllegalBlockSizeException) {
            // Handle exceptions related to illegal block sizes
            Log.d(APP_TAG, e.stackTraceToString())
            return null
        } catch (e: BadPaddingException) {
            // Handle exceptions related to bad padding
            Log.d(APP_TAG, e.stackTraceToString())
            return null
        } catch (e: IllegalArgumentException) {
            // Handle exceptions related to illegal argument
            Log.d(APP_TAG, e.stackTraceToString())
            return null
        }
    }

}