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
    fun getOrGenerateSecretKey(): SecretKey? {
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

}