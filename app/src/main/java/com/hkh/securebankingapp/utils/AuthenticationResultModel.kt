package com.hkh.securebankingapp.utils

import androidx.biometric.BiometricPrompt
import javax.crypto.Cipher


data class AuthenticationResultModel(
    val isSuccess: Boolean,
    val resultCode: Int,
    val cipher: Cipher? = null
) {
    fun isFailedToReadFingerPrint() =
        resultCode != BiometricPrompt.ERROR_USER_CANCELED &&
            resultCode != BiometricPrompt.ERROR_NEGATIVE_BUTTON &&
            resultCode != BiometricPrompt.ERROR_CANCELED
}
