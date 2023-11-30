package com.hkh.securebankingapp

import android.graphics.Color
import androidx.appcompat.app.AppCompatActivity
import android.os.Bundle
import android.view.View
import android.widget.Toast
import androidx.core.widget.addTextChangedListener
import androidx.lifecycle.ViewModelProvider
import com.hkh.securebankingapp.databinding.ActivityMainBinding
import com.hkh.securebankingapp.utils.FingerprintPrompt
import com.hkh.securebankingapp.utils.HexUtils.byteArrayToHex
import com.hkh.securebankingapp.utils.SecurityConstant.KEY_ALIAS_SYMMETRIC
import javax.crypto.Cipher

class MainActivity : AppCompatActivity() {

    private val fingerprintPrompt by lazy {
        FingerprintPrompt(this)
    }
    private var _binding: ActivityMainBinding? = null
    private val binding get() = _binding!!

    private lateinit var viewModel: MainActivityViewModel


    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        viewModel = ViewModelProvider(this)[MainActivityViewModel::class.java]
        _binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(_binding?.root)
        initActions()
    }

    private fun initActions() {
        observeIsKeyExist()
        observeShowErrorMessage()
        observeCheckKeyGeneration()
        observeCheckKeyRemove()
        observeCheckEncryptionMessage()
        observeEncryptedData()
        observeCheckDecryptionMessage()
        observeDecryptedData()

        checkKeyStatus()
        setupViews()
    }

    private fun observeIsKeyExist() = viewModel.isKeyExist.observe(this) {
        showToast(getString(if (it) R.string.key_is_exist else R.string.key_was_not_exist))
    }

    private fun observeShowErrorMessage() = viewModel.showErrorMessage.observe(this) {
        showToast(getString(it))
    }

    private fun observeCheckKeyGeneration() =
        viewModel.checkKeyGeneration.observe(this) {
            if (it) resetAllData(true)
            checkKeyStatus()
        }

    private fun observeCheckKeyRemove() =
        viewModel.checkKeyRemove.observe(this) {
            if (it) resetAllData(true)
            checkKeyStatus()
        }

    private fun observeCheckEncryptionMessage() =
        viewModel.checkEncryptionFlow.observe(this) { result ->
            openBiometric(result.second) { newCipher ->
                viewModel.encryptData(result.first, newCipher)
            }
        }

    private fun observeEncryptedData() =
        viewModel.encryptedData.observe(this) { data ->
            data?.let {
                binding.encryptedTextView.text = it.byteArrayToHex().trim()
            } ?: resetEncryptedText()
            resetDecryptedText()
        }

    private fun observeCheckDecryptionMessage() =
        viewModel.checkDecryptionFlow.observe(this) { result ->
            openBiometric(result.second) { newCipher ->
                viewModel.decryptData(result.first, newCipher)
            }
        }

    private fun observeDecryptedData() =
        viewModel.decryptedData.observe(this) { decryptedText ->
            decryptedText?.let {
                binding.decryptedTextView.text = it
            } ?: resetDecryptedText()
        }

    private fun setupViews() = with(binding) {
        if (!fingerprintPrompt.canAuthenticate()) errorView.visibility = View.VISIBLE
        generateKeyButton.setOnClickListener {
            viewModel.checkKeyGeneration()
        }
        removeKeyButton.setOnClickListener {
            viewModel.checkKeyRemove()
        }
        encryptKeyButton.setOnClickListener {
            viewModel.checkEncryption(binding.userInputEditText.text.toString())
        }
        decryptKeyButton.setOnClickListener {
            viewModel.checkDecryption(
                binding.encryptedTextView.text.toString(),
                getString(R.string.unknown_encrypted)
            )
        }
        userInputEditText.addTextChangedListener {
            resetAllData(false)
        }
    }

    private fun resetAllData(canResetInput: Boolean) {
        with(viewModel) {
            resetEncryptedData()
            resetDecryptedData()
        }
        if (canResetInput) binding.userInputEditText.setText("")
    }

    private fun resetEncryptedText() =
        binding.encryptedTextView.setText(getString(R.string.unknown_encrypted))

    private fun resetDecryptedText() =
        binding.decryptedTextView.setText(getString(R.string.unknown_decrypted))

    private fun checkKeyStatus() = binding.keyStatusTextView.apply {
        text = if (viewModel.keyStoreManager.isKeyExist(KEY_ALIAS_SYMMETRIC)) {
            setTextColor(GREEN_COLOR)
            getString(R.string.key_is_exist)
        } else {
            setTextColor(RED_COLOR)
            getString(R.string.key_was_not_exist)
        }
    }

    private fun openBiometric(cipher: Cipher?, onSuccess: (Cipher?) -> Unit) {
        fingerprintPrompt.show(
            title = getString(R.string.need_finger_print_for_operation),
            description = getString(R.string.cancel),
            cipher = cipher
        ).observe(this) { result ->
            if (result.isSuccess) {
                onSuccess.invoke(result.cipher)
            } else {
                if (result.isFailedToReadFingerPrint())
                    showToast(getString(R.string.failed_to_read_biometric))
            }
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        _binding = null
    }

    private fun showToast(message: String) {
        Toast.makeText(this, message, Toast.LENGTH_SHORT).show()
    }

    companion object {
        val GREEN_COLOR = Color.argb(255, 33, 103, 94)
        val RED_COLOR = Color.argb(255, 188, 19, 31)
    }
}