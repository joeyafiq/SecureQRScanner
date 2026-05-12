package com.example.secureqrscanner

import android.app.AlertDialog
import android.content.Intent
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.concurrent.TimeUnit

class LoadingActivity : AppCompatActivity() {

    private lateinit var tvLoadingMessage: TextView

    private val handler = Handler(Looper.getMainLooper())
    private var hasMovedToResult = false
    private var messageIndex = 0

    private val messages = listOf(
        "Reading QR content...",
        "Checking scan history...",
        "Checking VirusTotal...",
        "Checking Google Safe Browsing...",
        "Checking urlscan.io...",
        "Finalizing scan result..."
    )

    private val rescanMessages = listOf(
        "Rescanning URL...",
        "Ignoring previous history...",
        "Checking VirusTotal again...",
        "Checking Google Safe Browsing again...",
        "Checking urlscan.io again...",
        "Preparing fresh scan result..."
    )

    private fun startMessageAnimation(messagesToUse: List<String>) {
        messageIndex = 0

        val messageRunnable = object : Runnable {
            override fun run() {
                if (messageIndex < messagesToUse.size) {
                    tvLoadingMessage.text = messagesToUse[messageIndex]
                    messageIndex++
                }

                handler.postDelayed(this, 1200)
            }
        }

        handler.post(messageRunnable)
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_loading)

        tvLoadingMessage = findViewById(R.id.tvLoadingMessage)

        val scannedUrl = intent.getStringExtra("SCANNED_URL") ?: ""
        val forceRescan = intent.getBooleanExtra("FORCE_RESCAN", false)

        if (forceRescan) {
            startMessageAnimation(rescanMessages)
            runFullFreshScan(scannedUrl, true)
            return
        }

        startMessageAnimation(messages)

        val cachedResult = ScanHistoryManager.findByUrl(this, scannedUrl)

        if (cachedResult != null) {
            showRescanDialog(scannedUrl, cachedResult)
        } else {
            runFullFreshScan(scannedUrl, false)
        }
    }

    private fun showRescanDialog(
        scannedUrl: String,
        cachedResult: ScanHistoryItem
    ) {
        tvLoadingMessage.text = "This QR was scanned before."

        val oldWarning = if (isOlderThan24Hours(cachedResult.scannedAt)) {
            "\n\nThis previous result is older than 24 hours. Rescan is recommended for updated threat intelligence."
        } else {
            ""
        }

        AlertDialog.Builder(this)
            .setTitle("Previous Scan Found")
            .setMessage(
                "This QR code has already been scanned before.\n\n" +
                        "Previous result: ${cachedResult.riskLabel}\n" +
                        "Score: ${cachedResult.riskScore}/100\n" +
                        "Scan time: ${cachedResult.scannedAt}" +
                        oldWarning +
                        "\n\nDo you want to rescan it or use the previous result?"
            )
            .setPositiveButton("Rescan Anyway") { _, _ ->
                startMessageAnimation(rescanMessages)
                runFullFreshScan(scannedUrl, true)
            }
            .setNegativeButton("Use Previous Result") { _, _ ->
                openResultFromHistory(scannedUrl, cachedResult)
            }
            .setCancelable(false)
            .show()
    }

    private fun isOlderThan24Hours(scannedAt: String): Boolean {
        return try {
            val formatter = SimpleDateFormat("dd/MM/yyyy HH:mm", Locale.getDefault())
            val scannedDate = formatter.parse(scannedAt) ?: return false

            val currentTime = Date().time
            val scannedTime = scannedDate.time
            val diffMillis = currentTime - scannedTime

            diffMillis > TimeUnit.HOURS.toMillis(24)
        } catch (e: Exception) {
            false
        }
    }

    private fun openResultFromHistory(
        scannedUrl: String,
        cachedResult: ScanHistoryItem
    ) {
        if (hasMovedToResult) return
        hasMovedToResult = true

        val intent = Intent(this, ResultActivity::class.java)
        intent.putExtra("SCANNED_URL", scannedUrl)
        intent.putExtra("HISTORY_HIT", true)

        intent.putExtra("HISTORY_RISK_LABEL", cachedResult.riskLabel)
        intent.putExtra("HISTORY_RISK_SCORE", cachedResult.riskScore)
        intent.putExtra("HISTORY_SCANNED_AT", cachedResult.scannedAt)

        intent.putExtra("HISTORY_VALIDATION", cachedResult.validation)
        intent.putExtra("HISTORY_CHARACTERISTICS", cachedResult.characteristics)
        intent.putExtra("HISTORY_RISK_REASON", cachedResult.riskReason)

        intent.putExtra("HISTORY_VT_STATUS", cachedResult.virusTotalStatus)
        intent.putExtra("HISTORY_VT_DETAILS", cachedResult.virusTotalDetails)

        intent.putExtra("HISTORY_SB_STATUS", cachedResult.safeBrowsingStatus)
        intent.putExtra("HISTORY_SB_DETAILS", cachedResult.safeBrowsingDetails)

        intent.putExtra("HISTORY_URLSCAN_STATUS", cachedResult.urlScanStatus)
        intent.putExtra("HISTORY_URLSCAN_DETAILS", cachedResult.urlScanDetails)
        intent.putExtra("HISTORY_URLSCAN_DOMAIN", cachedResult.urlScanDomain)
        intent.putExtra("HISTORY_URLSCAN_IP", cachedResult.urlScanIp)
        intent.putExtra("HISTORY_URLSCAN_COUNTRY", cachedResult.urlScanCountry)
        intent.putExtra("HISTORY_URLSCAN_UUID", cachedResult.urlScanUuid)
        intent.putExtra("HISTORY_URLSCAN_SCREENSHOT_URL", cachedResult.urlScanScreenshotUrl)

        startActivity(intent)
        finish()
    }

    private fun runFullFreshScan(scannedUrl: String, forceRescan: Boolean) {
        var vtDone = false
        var sbDone = false
        var urlScanDone = false

        var vtStatus = "FAILED"
        var vtMalicious = 0
        var vtSuspicious = 0
        var vtHarmless = 0
        var vtUndetected = 0

        var sbStatus = "FAILED"
        var sbHasThreat = false
        var sbThreatTypes = ""

        var urlScanStatus = "Failed"
        var urlScanVerdict = "Not Available"
        var urlScanDetails = "urlscan.io check failed."
        var urlScanDomain = "-"
        var urlScanIp = "-"
        var urlScanCountry = "-"
        var urlScanUuid = "-"
        var urlScanScreenshotUrl = "-"

        fun tryOpenResult() {
            if (hasMovedToResult) return

            if (vtDone && sbDone && urlScanDone) {
                hasMovedToResult = true

                val intent = Intent(this, ResultActivity::class.java)
                intent.putExtra("SCANNED_URL", scannedUrl)
                intent.putExtra("HISTORY_HIT", false)
                intent.putExtra("FORCE_RESCAN", forceRescan)

                intent.putExtra("VT_STATUS", vtStatus)
                intent.putExtra("VT_MALICIOUS", vtMalicious)
                intent.putExtra("VT_SUSPICIOUS", vtSuspicious)
                intent.putExtra("VT_HARMLESS", vtHarmless)
                intent.putExtra("VT_UNDETECTED", vtUndetected)

                intent.putExtra("SB_STATUS", sbStatus)
                intent.putExtra("SB_HAS_THREAT", sbHasThreat)
                intent.putExtra("SB_THREAT_TYPES", sbThreatTypes)

                intent.putExtra("URLSCAN_STATUS", urlScanStatus)
                intent.putExtra("URLSCAN_VERDICT", urlScanVerdict)
                intent.putExtra("URLSCAN_DETAILS", urlScanDetails)
                intent.putExtra("URLSCAN_DOMAIN", urlScanDomain)
                intent.putExtra("URLSCAN_IP", urlScanIp)
                intent.putExtra("URLSCAN_COUNTRY", urlScanCountry)
                intent.putExtra("URLSCAN_UUID", urlScanUuid)
                intent.putExtra("URLSCAN_SCREENSHOT_URL", urlScanScreenshotUrl)

                startActivity(intent)
                finish()
            }
        }

        VirusTotalClient.checkUrl(scannedUrl) { stats ->
            runOnUiThread {
                if (stats != null) {
                    vtStatus = "SUCCESS"
                    vtMalicious = stats.malicious
                    vtSuspicious = stats.suspicious
                    vtHarmless = stats.harmless
                    vtUndetected = stats.undetected
                } else {
                    vtStatus = "FAILED"
                }

                vtDone = true
                tryOpenResult()
            }
        }

        SafeBrowsingClient.checkUrl(scannedUrl) { result ->
            runOnUiThread {
                if (result != null) {
                    sbStatus = "SUCCESS"
                    sbHasThreat = result.hasThreat
                    sbThreatTypes = result.threatTypes.joinToString(", ")
                } else {
                    sbStatus = "FAILED"
                    sbHasThreat = false
                    sbThreatTypes = ""
                }

                sbDone = true
                tryOpenResult()
            }
        }

        UrlScanClient.scanUrl(scannedUrl) { result ->
            runOnUiThread {
                if (result != null) {
                    urlScanStatus = result.status
                    urlScanVerdict = result.verdict
                    urlScanDetails = result.details
                    urlScanDomain = result.domain
                    urlScanIp = result.ip
                    urlScanCountry = result.country
                    urlScanUuid = result.uuid
                    urlScanScreenshotUrl = result.screenshotUrl
                } else {
                    urlScanStatus = "Failed"
                    urlScanVerdict = "Not Available"
                    urlScanDetails = "urlscan.io check failed."
                    urlScanDomain = "-"
                    urlScanIp = "-"
                    urlScanCountry = "-"
                    urlScanUuid = "-"
                    urlScanScreenshotUrl = "-"
                }

                urlScanDone = true
                tryOpenResult()
            }
        }

        handler.postDelayed({
            if (!vtDone) {
                vtStatus = "TIMEOUT"
                vtDone = true
            }

            if (!sbDone) {
                sbStatus = "TIMEOUT"
                sbHasThreat = false
                sbThreatTypes = ""
                sbDone = true
            }

            if (!urlScanDone) {
                urlScanStatus = "Timeout"
                urlScanVerdict = "Not Available"
                urlScanDetails = "urlscan.io did not finish within the allowed waiting time."
                urlScanDomain = "-"
                urlScanIp = "-"
                urlScanCountry = "-"
                urlScanUuid = "-"
                urlScanScreenshotUrl = "-"
                urlScanDone = true
            }

            tryOpenResult()
        }, 45000)
    }

    override fun onDestroy() {
        super.onDestroy()
        handler.removeCallbacksAndMessages(null)
    }
}