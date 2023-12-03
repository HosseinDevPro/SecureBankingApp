package com.hkh.securebankingapp

import androidx.lifecycle.LiveData
import androidx.lifecycle.MutableLiveData
import androidx.lifecycle.ViewModel
import com.hkh.securebankingapp.cryptography.CryptographyManagerImpl
import com.hkh.securebankingapp.utils.SecurityConstant
import com.hkh.securebankingapp.utils.KeyStoreManager
import com.hkh.securebankingapp.cryptography.SymmetricKeyGeneration
import com.hkh.securebankingapp.utils.HexUtils.hexToByteArray
import com.hkh.securebankingapp.utils.SecurityConstant.INITIAL_VECTOR_SIZE
import javax.crypto.Cipher

class MainActivityViewModel : ViewModel() {

    var supportStrongBox = false

    val keyStoreManager by lazy {
        KeyStoreManager()
    }
    private val symmetricKeyGenerationUtil by lazy {
        SymmetricKeyGeneration(supportStrongBox, keyStoreManager)
    }

    private val cryptography by lazy {
        CryptographyManagerImpl(keyStoreManager)
    }

    private val _encryptedData = MutableLiveData<ByteArray?>()
    val encryptedData: LiveData<ByteArray?> = _encryptedData
    fun resetEncryptedData() {
        _encryptedData.value = null
    }

    private val _decryptedData = MutableLiveData<String?>()
    val decryptedData: LiveData<String?> = _decryptedData
    fun resetDecryptedData() {
        _decryptedData.value = null
    }


    private val _isKeyExist = MutableLiveData<Boolean>()
    val isKeyExist: LiveData<Boolean> = _isKeyExist

    private val _showErrorMessage = MutableLiveData<Int>()
    val showErrorMessage: LiveData<Int> = _showErrorMessage


    private val _checkKeyGeneration = MutableLiveData<Boolean>()
    val checkKeyGeneration: LiveData<Boolean> = _checkKeyGeneration

    fun checkKeyGeneration() {
        if (!keyStoreManager.isKeyExist(SecurityConstant.KEY_ALIAS_SYMMETRIC)) {
            symmetricKeyGenerationUtil.getOrGenerateSecretKey()
            _checkKeyGeneration.value = true
        } else {
            _isKeyExist.value = true
        }
    }

    private val _checkKeyRemove = MutableLiveData<Boolean>()
    val checkKeyRemove: LiveData<Boolean> = _checkKeyRemove
    fun checkKeyRemove() {
        if (keyStoreManager.isKeyExist(SecurityConstant.KEY_ALIAS_SYMMETRIC)) {
            keyStoreManager.removeKey(SecurityConstant.KEY_ALIAS_SYMMETRIC)
            _checkKeyRemove.value = true
        } else {
            _isKeyExist.value = false
        }
    }


    private val _checkEncryptionFlow = MutableLiveData<Pair<String, Cipher>>()
    val checkEncryptionFlow: LiveData<Pair<String, Cipher>> = _checkEncryptionFlow
    fun checkEncryption(userInputText: String) {
        if (userInputText.isNotEmpty()) {
            if (keyStoreManager.isKeyExist(SecurityConstant.KEY_ALIAS_SYMMETRIC)) {
                val cipher = buildCipherForEncryption()
                if (cipher != null) {
                    _checkEncryptionFlow.value = Pair(userInputText, cipher)
                } else {
                    _showErrorMessage.value = R.string.an_error_occurred
                }
            } else {
                _isKeyExist.value = false
            }
        } else {
            _showErrorMessage.value = R.string.user_input_is_empty
        }
    }

    private fun buildCipherForEncryption(): Cipher? {
        return cryptography.getInitializedCipherForEncryption()
    }

    fun encryptData(userInputText: String, cipher: Cipher?) {
        _encryptedData.value = cryptography.encryptData(userInputText, cipher)
    }


    private val _checkDecryptionFlow = MutableLiveData<Pair<String, Cipher>>()
    val checkDecryptionFlow: LiveData<Pair<String, Cipher>> = _checkDecryptionFlow
    fun checkDecryption(encryptedText: String, defaultText: String) {
        if (encryptedText != defaultText) {
            if (keyStoreManager.isKeyExist(SecurityConstant.KEY_ALIAS_SYMMETRIC)) {
                val cipher = buildCipherForDecryption(encryptedText)
                if (cipher != null) {
                    _checkDecryptionFlow.value = Pair(encryptedText, cipher)
                } else {
                    _showErrorMessage.value = R.string.an_error_occurred
                }
            } else {
                _isKeyExist.value = false
            }
        } else {
            _showErrorMessage.value = R.string.encrypted_text_is_empty
        }
    }

    private fun buildCipherForDecryption(encryptedText: String): Cipher? {
        // Decode the Hex-encoded (iv + encrypted_text) into bytes
        val fullBytes = encryptedText.hexToByteArray()
        // Extract iv 12 bytes
        val iv = fullBytes.sliceArray(0 .. INITIAL_VECTOR_SIZE-1)
        return cryptography.getInitializedCipherForDecryption(iv)
    }

    fun decryptData(encryptedText: String, cipher: Cipher?) {
        // Decode the Hex-encoded (iv + encrypted_text) into bytes
        val fullBytes = encryptedText.hexToByteArray()
        // Extract all other ciphered bytes
        val encryptedBytes = fullBytes.sliceArray(INITIAL_VECTOR_SIZE.. fullBytes.lastIndex)
        _decryptedData.value = cryptography.decryptData(encryptedBytes, cipher)
    }

}