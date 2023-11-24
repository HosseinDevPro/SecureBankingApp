package com.hkh.securebankingapp

import androidx.lifecycle.LiveData
import androidx.lifecycle.MutableLiveData
import androidx.lifecycle.ViewModel
import com.hkh.securebankingapp.utils.SecurityConstant
import com.hkh.securebankingapp.utils.KeyStoreManager
import com.hkh.securebankingapp.cryptography.SymmetricKeyGeneration

class MainActivityViewModel : ViewModel() {

    val keyStoreManager by lazy {
        KeyStoreManager()
    }
    private val symmetricKeyGenerationUtil by lazy {
        SymmetricKeyGeneration(keyStoreManager)
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
            symmetricKeyGenerationUtil.getOrGenerateKey()
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


    private val _checkEncryptionMessage = MutableLiveData<String>()
    val checkEncryptionMessage: LiveData<String> = _checkEncryptionMessage
    fun checkEncryption(userInputText: String) {
        if (userInputText.isNotEmpty()) {
            if (keyStoreManager.isKeyExist(SecurityConstant.KEY_ALIAS_SYMMETRIC)) {
                _checkEncryptionMessage.value = userInputText
            } else {
                _isKeyExist.value = false
            }
        } else {
            _showErrorMessage.value = R.string.user_input_is_empty
        }
    }

    fun encryptData(userInputText: String) {
        _encryptedData.value = symmetricKeyGenerationUtil.encrypt(userInputText)
    }


    private val _checkDecryptionMessage = MutableLiveData<String>()
    val checkDecryptionMessage: LiveData<String> = _checkDecryptionMessage
    fun checkDecryption(encryptedText: String, defaultText: String) {
        if (encryptedText != defaultText) {
            if (keyStoreManager.isKeyExist(SecurityConstant.KEY_ALIAS_SYMMETRIC)) {
                _checkDecryptionMessage.value = encryptedText
            } else {
                _isKeyExist.value = false
            }
        } else {
            _showErrorMessage.value = R.string.encrypted_text_is_empty
        }
    }

    fun decryptData(encryptedText: String) {
        _decryptedData.value = symmetricKeyGenerationUtil.decrypt(encryptedText)
    }

}