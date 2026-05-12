package com.example.secureqrscanner

object ApiConfig {

    var VIRUSTOTAL_API_KEY: String = ""
    var GOOGLE_SAFE_BROWSING_API_KEY: String = ""
    var URLSCAN_API_KEY: String = ""

    fun hasAllApiKeys(): Boolean {
        return VIRUSTOTAL_API_KEY.isNotBlank() &&
                GOOGLE_SAFE_BROWSING_API_KEY.isNotBlank() &&
                URLSCAN_API_KEY.isNotBlank()
    }

    fun clear() {
        VIRUSTOTAL_API_KEY = ""
        GOOGLE_SAFE_BROWSING_API_KEY = ""
        URLSCAN_API_KEY = ""
    }
}