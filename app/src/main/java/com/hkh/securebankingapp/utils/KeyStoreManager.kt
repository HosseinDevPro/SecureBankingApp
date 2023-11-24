package com.hkh.securebankingapp.utils

import android.util.Log
import com.hkh.securebankingapp.utils.SecurityConstant.ANDROID_KEY_STORE_PROVIDER
import com.hkh.securebankingapp.utils.SecurityConstant.APP_TAG
import java.security.KeyStore
import java.security.KeyStoreException
import java.security.NoSuchAlgorithmException
import java.security.UnrecoverableKeyException
import java.util.Enumeration
import javax.crypto.SecretKey

class KeyStoreManager {

    private val keyStore: KeyStore by lazy {
        KeyStore.getInstance(ANDROID_KEY_STORE_PROVIDER).apply {
            load(null)
        }
    }

    fun removeAllKeys() = try {
        val aliases: Enumeration<String> = keyStore.aliases()
        aliases.toList().forEach {
            keyStore.deleteEntry(it)
        }
    } catch (e: KeyStoreException) {
        Log.d(APP_TAG, e.stackTraceToString())
    }

    fun removeKey(alias: String) = try {
        keyStore.deleteEntry(alias)
    } catch (e: KeyStoreException) {
        Log.d(APP_TAG, e.stackTraceToString())
    }

    fun isKeyExist(keyAlias: String) = try {
        keyStore.containsAlias(keyAlias)
    } catch (e: KeyStoreException) {
        Log.d(APP_TAG, e.stackTraceToString())
        false
    }

    fun getKeyWithAlias(keyAlias: String): SecretKey? = try {
        (keyStore.getEntry(keyAlias, null) as KeyStore.SecretKeyEntry).secretKey
    } catch (e: KeyStoreException) {
        Log.d(APP_TAG, e.stackTraceToString())
        null
    } catch (e: NoSuchAlgorithmException) {
        Log.d(APP_TAG, e.stackTraceToString())
        null
    } catch (e: UnrecoverableKeyException) {
        Log.d(APP_TAG, e.stackTraceToString())
        null
    }

}
