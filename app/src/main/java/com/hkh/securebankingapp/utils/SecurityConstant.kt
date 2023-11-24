package com.hkh.securebankingapp.utils

import androidx.biometric.BiometricManager

object SecurityConstant {

    const val APP_TAG = "SecureBankingAppTAG"
    const val ANDROID_KEY_STORE_PROVIDER = "AndroidKeyStore"
    const val KEY_ALIAS_SYMMETRIC = "AES_KEY_DEMO"
    const val KEY_SIZE = 256
    const val AES_GCM_NOPADDING = "AES/GCM/NoPadding"
    const val AUTHENTICATION_TAG_SIZE = 128
    const val AUTHENTICATION_VALIDITY_DURATION = 10
    const val INITIAL_VECTOR_SIZE = 12

    const val AUTHENTICATORS = BiometricManager.Authenticators.BIOMETRIC_STRONG

}