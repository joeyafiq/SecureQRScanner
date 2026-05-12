package com.example.secureqrscanner

data class ScanHistoryItem(
    val url: String,
    val riskLabel: String,
    val riskScore: Int,
    val scannedAt: String,
    val validation: String,
    val characteristics: String,
    val riskReason: String,

    val redirectChain: String = "Redirection information was not saved.",

    val virusTotalStatus: String,
    val virusTotalDetails: String,

    val safeBrowsingStatus: String,
    val safeBrowsingDetails: String,

    val urlScanStatus: String = "Not Available",
    val urlScanDetails: String = "urlscan.io result was not saved.",
    val urlScanDomain: String = "-",
    val urlScanIp: String = "-",
    val urlScanCountry: String = "-",
    val urlScanUuid: String = "-",
    val urlScanScreenshotUrl: String = "-"
)