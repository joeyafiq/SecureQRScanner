package com.example.secureqrscanner

import android.content.Context
import android.content.SharedPreferences
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.security.KeyStore
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec

object SessionManager {

    private const val PREF_NAME = "secure_qr_user_session"

    private const val KEY_IS_SETUP_DONE = "is_setup_done"
    private const val KEY_IS_LOGGED_IN = "is_logged_in"

    private const val KEY_USERNAME = "username"

    // Password is no longer stored directly.
    // We store only hash + salt.
    private const val KEY_PASSWORD_HASH = "password_hash"
    private const val KEY_PASSWORD_SALT = "password_salt"

    // Encrypted API keys + IVs
    private const val KEY_VIRUSTOTAL_API = "virustotal_api_key_encrypted"
    private const val KEY_VIRUSTOTAL_IV = "virustotal_api_key_iv"

    private const val KEY_SAFE_BROWSING_API = "safe_browsing_api_key_encrypted"
    private const val KEY_SAFE_BROWSING_IV = "safe_browsing_api_key_iv"

    private const val KEY_URLSCAN_API = "urlscan_api_key_encrypted"
    private const val KEY_URLSCAN_IV = "urlscan_api_key_iv"

    private const val LEGACY_KEY_PASSWORD = "password"
    private const val LEGACY_KEY_VIRUSTOTAL_API = "virustotal_api_key"
    private const val LEGACY_KEY_SAFE_BROWSING_API = "safe_browsing_api_key"
    private const val LEGACY_KEY_URLSCAN_API = "urlscan_api_key"

    // Android Keystore settings
    private const val ANDROID_KEYSTORE = "AndroidKeyStore"
    private const val KEY_ALIAS = "SecureQRScannerApiKeyAlias"

    // Password hashing settings
    private const val PBKDF2_ALGORITHM = "PBKDF2WithHmacSHA256"
    private const val HASH_ITERATIONS = 120_000
    private const val HASH_KEY_LENGTH = 256

    data class EncryptedData(
        val encryptedText: String,
        val iv: String
    )

    private fun getPrefs(context: Context): SharedPreferences {
        return context.getSharedPreferences(PREF_NAME, Context.MODE_PRIVATE)
    }

    fun saveAccount(
        context: Context,
        username: String,
        password: String,
        virusTotalApiKey: String,
        safeBrowsingApiKey: String,
        urlScanApiKey: String
    ) {
        val prefs = getPrefs(context)

        val salt = generateSalt()
        val passwordHash = hashPassword(password, salt)

        val encryptedVirusTotal = encryptText(virusTotalApiKey)
        val encryptedSafeBrowsing = encryptText(safeBrowsingApiKey)
        val encryptedUrlScan = encryptText(urlScanApiKey)

        prefs.edit()
            .putBoolean(KEY_IS_SETUP_DONE, true)
            .putBoolean(KEY_IS_LOGGED_IN, false)

            .putString(KEY_USERNAME, username)

            .putString(KEY_PASSWORD_HASH, passwordHash)
            .putString(KEY_PASSWORD_SALT, Base64.encodeToString(salt, Base64.NO_WRAP))

            .putString(KEY_VIRUSTOTAL_API, encryptedVirusTotal.encryptedText)
            .putString(KEY_VIRUSTOTAL_IV, encryptedVirusTotal.iv)

            .putString(KEY_SAFE_BROWSING_API, encryptedSafeBrowsing.encryptedText)
            .putString(KEY_SAFE_BROWSING_IV, encryptedSafeBrowsing.iv)

            .putString(KEY_URLSCAN_API, encryptedUrlScan.encryptedText)
            .putString(KEY_URLSCAN_IV, encryptedUrlScan.iv)

            .remove(LEGACY_KEY_PASSWORD)
            .remove(LEGACY_KEY_VIRUSTOTAL_API)
            .remove(LEGACY_KEY_SAFE_BROWSING_API)
            .remove(LEGACY_KEY_URLSCAN_API)

            .apply()
    }

    fun isSetupDone(context: Context): Boolean {
        return getPrefs(context).getBoolean(KEY_IS_SETUP_DONE, false)
    }

    fun login(
        context: Context,
        username: String,
        password: String
    ): Boolean {
        val prefs = getPrefs(context)

        val savedUsername = prefs.getString(KEY_USERNAME, "") ?: ""
        val savedPasswordHash = prefs.getString(KEY_PASSWORD_HASH, "") ?: ""
        val savedSaltBase64 = prefs.getString(KEY_PASSWORD_SALT, "") ?: ""

        if (savedUsername.isBlank() || savedPasswordHash.isBlank() || savedSaltBase64.isBlank()) {
            return false
        }

        if (username != savedUsername) {
            return false
        }

        val salt = Base64.decode(savedSaltBase64, Base64.NO_WRAP)
        val enteredPasswordHash = hashPassword(password, salt)

        val isCorrect = enteredPasswordHash == savedPasswordHash

        if (isCorrect) {
            prefs.edit()
                .putBoolean(KEY_IS_LOGGED_IN, true)
                .apply()

            loadApiKeysToConfig(context)
        }

        return isCorrect
    }

    fun logout(context: Context) {
        getPrefs(context).edit()
            .putBoolean(KEY_IS_LOGGED_IN, false)
            .apply()

        ApiConfig.clear()
    }

    fun isLoggedIn(context: Context): Boolean {
        return getPrefs(context).getBoolean(KEY_IS_LOGGED_IN, false)
    }

    fun loadApiKeysToConfig(context: Context) {
        val prefs = getPrefs(context)
        removeLegacyPlaintextSecrets(prefs)

        val vtEncrypted = prefs.getString(KEY_VIRUSTOTAL_API, "") ?: ""
        val vtIv = prefs.getString(KEY_VIRUSTOTAL_IV, "") ?: ""

        val safeBrowsingEncrypted = prefs.getString(KEY_SAFE_BROWSING_API, "") ?: ""
        val safeBrowsingIv = prefs.getString(KEY_SAFE_BROWSING_IV, "") ?: ""

        val urlScanEncrypted = prefs.getString(KEY_URLSCAN_API, "") ?: ""
        val urlScanIv = prefs.getString(KEY_URLSCAN_IV, "") ?: ""

        ApiConfig.VIRUSTOTAL_API_KEY =
            if (vtEncrypted.isNotBlank() && vtIv.isNotBlank()) {
                decryptText(vtEncrypted, vtIv)
            } else {
                ""
            }

        ApiConfig.GOOGLE_SAFE_BROWSING_API_KEY =
            if (safeBrowsingEncrypted.isNotBlank() && safeBrowsingIv.isNotBlank()) {
                decryptText(safeBrowsingEncrypted, safeBrowsingIv)
            } else {
                ""
            }

        ApiConfig.URLSCAN_API_KEY =
            if (urlScanEncrypted.isNotBlank() && urlScanIv.isNotBlank()) {
                decryptText(urlScanEncrypted, urlScanIv)
            } else {
                ""
            }
    }

    fun hasApiKeys(context: Context): Boolean {
        return try {
            loadApiKeysToConfig(context)

            ApiConfig.VIRUSTOTAL_API_KEY.isNotBlank() &&
                    ApiConfig.GOOGLE_SAFE_BROWSING_API_KEY.isNotBlank() &&
                    ApiConfig.URLSCAN_API_KEY.isNotBlank()
        } catch (e: Exception) {
            false
        }
    }

    private fun removeLegacyPlaintextSecrets(prefs: SharedPreferences) {
        prefs.edit()
            .remove(LEGACY_KEY_PASSWORD)
            .remove(LEGACY_KEY_VIRUSTOTAL_API)
            .remove(LEGACY_KEY_SAFE_BROWSING_API)
            .remove(LEGACY_KEY_URLSCAN_API)
            .apply()
    }

    fun clearAccount(context: Context) {
        getPrefs(context).edit()
            .clear()
            .apply()

        ApiConfig.clear()
    }

    private fun generateSalt(): ByteArray {
        val salt = ByteArray(32)
        SecureRandom().nextBytes(salt)
        return salt
    }

    private fun hashPassword(
        password: String,
        salt: ByteArray
    ): String {
        val spec = PBEKeySpec(
            password.toCharArray(),
            salt,
            HASH_ITERATIONS,
            HASH_KEY_LENGTH
        )

        val factory = SecretKeyFactory.getInstance(PBKDF2_ALGORITHM)
        val hash = factory.generateSecret(spec).encoded

        return Base64.encodeToString(hash, Base64.NO_WRAP)
    }

    private fun getOrCreateSecretKey(): SecretKey {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE)
        keyStore.load(null)

        val existingKey = keyStore.getEntry(KEY_ALIAS, null) as? KeyStore.SecretKeyEntry

        if (existingKey != null) {
            return existingKey.secretKey
        }

        val keyGenerator = KeyGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_AES,
            ANDROID_KEYSTORE
        )

        val keySpec = KeyGenParameterSpec.Builder(
            KEY_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .build()

        keyGenerator.init(keySpec)

        return keyGenerator.generateKey()
    }

    private fun encryptText(plainText: String): EncryptedData {
        val secretKey = getOrCreateSecretKey()

        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, secretKey)

        val iv = cipher.iv
        val encryptedBytes = cipher.doFinal(plainText.toByteArray(Charsets.UTF_8))

        return EncryptedData(
            encryptedText = Base64.encodeToString(encryptedBytes, Base64.NO_WRAP),
            iv = Base64.encodeToString(iv, Base64.NO_WRAP)
        )
    }

    private fun decryptText(
        encryptedText: String,
        ivText: String
    ): String {
        val secretKey = getOrCreateSecretKey()

        val encryptedBytes = Base64.decode(encryptedText, Base64.NO_WRAP)
        val iv = Base64.decode(ivText, Base64.NO_WRAP)

        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val gcmSpec = GCMParameterSpec(128, iv)

        cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmSpec)

        val decryptedBytes = cipher.doFinal(encryptedBytes)

        return String(decryptedBytes, Charsets.UTF_8)
    }
}
