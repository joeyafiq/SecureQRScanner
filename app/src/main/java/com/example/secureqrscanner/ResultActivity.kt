package com.example.secureqrscanner

import android.app.AlertDialog
import android.content.ClipData
import android.content.Intent
import android.content.res.ColorStateList
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.graphics.Color
import android.graphics.Matrix
import android.graphics.Paint
import android.graphics.RectF
import android.graphics.pdf.PdfDocument
import android.net.Uri
import android.os.Bundle
import android.os.CountDownTimer
import android.util.Patterns
import android.view.MotionEvent
import android.view.ScaleGestureDetector
import android.widget.Button
import android.widget.FrameLayout
import android.widget.ImageView
import android.widget.ProgressBar
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.FileProvider
import okhttp3.OkHttpClient
import okhttp3.Request
import java.io.File
import java.io.FileOutputStream
import java.net.URI
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.concurrent.TimeUnit

class ResultActivity : AppCompatActivity() {

    private data class RuleFinding(
        val message: String,
        val score: Int
    )

    private var vtStats: VirusTotalClient.VirusTotalStats? = null
    private var sbResult: SafeBrowsingClient.SafeBrowsingResult? = null
    private var ruleFindings: MutableList<RuleFinding> = mutableListOf()
    private var virusTotalCheckStatus = "NOT_AVAILABLE"
    private var safeBrowsingCheckStatus = "NOT_AVAILABLE"
    private var urlScanCheckStatus = "NOT_AVAILABLE"

    private var currentRiskLabel = "UNKNOWN"
    private var scannedUrl = ""
    private var hasSavedHistory = false
    private var safeBrowsingFinished = false
    private var redirectFinished = false
    private var currentScanTime = ""

    private var currentRedirectChain = "Checking redirects..."

    private var currentUrlScanStatus = "Not Available"
    private var currentUrlScanDetails = "-"
    private var currentUrlScanDomain = "-"
    private var currentUrlScanIp = "-"
    private var currentUrlScanCountry = "-"
    private var currentUrlScanUuid = "-"
    private var currentUrlScanScreenshotUrl = "-"

    private var currentScreenshotBitmap: Bitmap? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_result)

        val tvRiskLabel = findViewById<TextView>(R.id.tvRiskLabel)
        val tvRiskScore = findViewById<TextView>(R.id.tvRiskScore)
        val progressRisk = findViewById<ProgressBar>(R.id.progressRisk)
        val tvScoreGuide = findViewById<TextView>(R.id.tvScoreGuide)
        val tvConfidence = findViewById<TextView>(R.id.tvConfidence)
        val tvRiskReason = findViewById<TextView>(R.id.tvRiskReason)

        val tvScannedUrl = findViewById<TextView>(R.id.tvScannedUrl)
        val tvScanInfo = findViewById<TextView>(R.id.tvScanInfo)
        val tvValidation = findViewById<TextView>(R.id.tvValidation)
        val tvUrlMetadata = findViewById<TextView>(R.id.tvUrlMetadata)
        val tvRedirectChain = findViewById<TextView>(R.id.tvRedirectChain)
        val tvCharacteristics = findViewById<TextView>(R.id.tvCharacteristics)

        val tvVirusTotalStatus = findViewById<TextView>(R.id.tvVirusTotalStatus)
        val tvVirusTotalDetails = findViewById<TextView>(R.id.tvVirusTotalDetails)

        val tvSafeBrowsingStatus = findViewById<TextView>(R.id.tvSafeBrowsingStatus)
        val tvSafeBrowsingDetails = findViewById<TextView>(R.id.tvSafeBrowsingDetails)

        val tvUrlScanStatus = findViewById<TextView>(R.id.tvUrlScanStatus)
        val tvUrlScanDetails = findViewById<TextView>(R.id.tvUrlScanDetails)

        val ivUrlScanScreenshot = findViewById<ImageView>(R.id.ivUrlScanScreenshot)
        val tvScreenshotHint = findViewById<TextView>(R.id.tvScreenshotHint)

        val btnOpenLink = findViewById<Button>(R.id.btnOpenLink)
        val btnSharePdf = findViewById<Button>(R.id.btnSharePdf)

        currentScanTime = SimpleDateFormat(
            "dd/MM/yyyy HH:mm",
            Locale.getDefault()
        ).format(Date())

        val receivedContent = intent.getStringExtra("SCANNED_URL") ?: "No content received"
        val isHistoryHit = intent.getBooleanExtra("HISTORY_HIT", false)
        val forceRescan = intent.getBooleanExtra("FORCE_RESCAN", false)

        scannedUrl = receivedContent
        tvScannedUrl.text = receivedContent

        tvScanInfo.text = if (forceRescan) {
            "Fresh rescan\n$currentScanTime"
        } else {
            "New scan\n$currentScanTime"
        }

        btnOpenLink.isEnabled = false

        tvScoreGuide.setOnClickListener {
            showScoreGuideDialog()
        }

        btnOpenLink.setOnClickListener {
            if (currentRiskLabel == "SAFE") {
                openUrl(scannedUrl)
            } else {
                showWarningDialog(currentRiskLabel, scannedUrl)
            }
        }

        btnSharePdf.setOnClickListener {
            createAndSharePdfReport(
                tvRiskLabel = tvRiskLabel,
                tvRiskScore = tvRiskScore,
                tvConfidence = tvConfidence,
                tvScannedUrl = tvScannedUrl,
                tvScanInfo = tvScanInfo,
                tvValidation = tvValidation,
                tvUrlMetadata = tvUrlMetadata,
                tvRedirectChain = tvRedirectChain,
                tvRiskReason = tvRiskReason,
                tvCharacteristics = tvCharacteristics,
                tvVirusTotalStatus = tvVirusTotalStatus,
                tvVirusTotalDetails = tvVirusTotalDetails,
                tvSafeBrowsingStatus = tvSafeBrowsingStatus,
                tvSafeBrowsingDetails = tvSafeBrowsingDetails,
                tvUrlScanStatus = tvUrlScanStatus,
                tvUrlScanDetails = tvUrlScanDetails
            )
        }

        if (isHistoryHit) {
            loadHistoryResult(
                tvRiskLabel,
                tvRiskScore,
                progressRisk,
                tvConfidence,
                tvRiskReason,
                tvScanInfo,
                tvValidation,
                tvUrlMetadata,
                tvRedirectChain,
                tvCharacteristics,
                tvVirusTotalStatus,
                tvVirusTotalDetails,
                tvSafeBrowsingStatus,
                tvSafeBrowsingDetails,
                tvUrlScanStatus,
                tvUrlScanDetails,
                ivUrlScanScreenshot,
                tvScreenshotHint,
                btnOpenLink
            )
            return
        }

        if (isValidWebUrl(receivedContent)) {
            tvValidation.text = "Valid URL detected"
            btnOpenLink.isEnabled = true

            ruleFindings = analyzeUrlStatic(receivedContent).toMutableList()
            updateCharacteristics(tvCharacteristics)

            vtStats = getVirusTotalFromIntent()
            updateVirusTotalFromLoadingIntent(tvVirusTotalStatus, tvVirusTotalDetails)

            loadSafeBrowsingFromIntent(tvSafeBrowsingStatus, tvSafeBrowsingDetails)

            loadUrlScanFromIntent(
                statusView = tvUrlScanStatus,
                detailsView = tvUrlScanDetails,
                metadataView = tvUrlMetadata,
                imageView = ivUrlScanScreenshot,
                hintView = tvScreenshotHint
            )

            updateFinalRiskUI(
                tvRiskLabel,
                tvRiskScore,
                progressRisk,
                tvConfidence,
                tvRiskReason
            )

            checkRedirectsInBackground(
                url = receivedContent,
                tvCharacteristics = tvCharacteristics,
                tvRedirectChain = tvRedirectChain,
                tvRiskLabel = tvRiskLabel,
                tvRiskScore = tvRiskScore,
                progressRisk = progressRisk,
                tvConfidence = tvConfidence,
                tvRiskReason = tvRiskReason
            )

        } else {
            tvValidation.text = "This QR does not contain a valid URL"
            tvUrlMetadata.text = "Not available"

            currentRedirectChain = "Redirection analysis not performed"
            tvRedirectChain.text = currentRedirectChain

            tvCharacteristics.text = "URL analysis not performed"

            tvVirusTotalStatus.text = "Not Performed"
            tvVirusTotalStatus.setTextColor(Color.GRAY)
            tvVirusTotalDetails.text = "Threat intelligence check not performed"

            tvSafeBrowsingStatus.text = "Not Performed"
            tvSafeBrowsingStatus.setTextColor(Color.GRAY)
            tvSafeBrowsingDetails.text = "Threat intelligence check not performed"

            tvUrlScanStatus.text = "Not Performed"
            tvUrlScanStatus.setTextColor(Color.GRAY)
            tvUrlScanDetails.text = "Threat intelligence check not performed"

            tvRiskLabel.text = "INVALID"
            tvRiskLabel.setTextColor(Color.GRAY)
            tvRiskScore.text = "Score: 0/100"
            tvScoreGuide.text = "ⓘ Score guide: not available for invalid QR content"
            progressRisk.progress = 0
            tvConfidence.text = "Confidence: None"
            tvRiskReason.text =
                "The scanned QR content is not a valid web URL, so URL risk analysis was not performed."

            currentRiskLabel = "INVALID"

            showScreenshotMessage(
                imageView = ivUrlScanScreenshot,
                hintView = tvScreenshotHint,
                message = "Screenshot not available"
            )
        }
    }

    private fun loadHistoryResult(
        tvRiskLabel: TextView,
        tvRiskScore: TextView,
        progressRisk: ProgressBar,
        tvConfidence: TextView,
        tvRiskReason: TextView,
        tvScanInfo: TextView,
        tvValidation: TextView,
        tvUrlMetadata: TextView,
        tvRedirectChain: TextView,
        tvCharacteristics: TextView,
        tvVirusTotalStatus: TextView,
        tvVirusTotalDetails: TextView,
        tvSafeBrowsingStatus: TextView,
        tvSafeBrowsingDetails: TextView,
        tvUrlScanStatus: TextView,
        tvUrlScanDetails: TextView,
        ivUrlScanScreenshot: ImageView,
        tvScreenshotHint: TextView,
        btnOpenLink: Button
    ) {
        val cachedLabel = intent.getStringExtra("HISTORY_RISK_LABEL") ?: "UNKNOWN"
        val cachedScore = intent.getIntExtra("HISTORY_RISK_SCORE", 0)
        val cachedDate = intent.getStringExtra("HISTORY_SCANNED_AT") ?: "-"

        val cachedValidation = intent.getStringExtra("HISTORY_VALIDATION")
            ?: "Validation result not available"

        val cachedCharacteristics = intent.getStringExtra("HISTORY_CHARACTERISTICS")
            ?: "No saved characteristics available"

        val cachedRiskReason = intent.getStringExtra("HISTORY_RISK_REASON")
            ?: "No saved risk reason available"

        val cachedRedirectChain = intent.getStringExtra("HISTORY_REDIRECT_CHAIN")
            ?: "Redirection information was not saved."

        val cachedVtStatus = intent.getStringExtra("HISTORY_VT_STATUS")
            ?: "Not Available"

        val cachedVtDetails = intent.getStringExtra("HISTORY_VT_DETAILS")
            ?: "No saved VirusTotal result available"

        val cachedSbStatus = intent.getStringExtra("HISTORY_SB_STATUS")
            ?: "Not Available"

        val cachedSbDetails = intent.getStringExtra("HISTORY_SB_DETAILS")
            ?: "No saved Google Safe Browsing result available"

        val cachedUrlScanStatus = intent.getStringExtra("HISTORY_URLSCAN_STATUS")
            ?: "Not Available"

        val cachedUrlScanDetails = intent.getStringExtra("HISTORY_URLSCAN_DETAILS")
            ?: "urlscan.io result was not saved."

        val cachedUrlScanDomain = intent.getStringExtra("HISTORY_URLSCAN_DOMAIN") ?: "-"
        val cachedUrlScanIp = intent.getStringExtra("HISTORY_URLSCAN_IP") ?: "-"
        val cachedUrlScanCountry = intent.getStringExtra("HISTORY_URLSCAN_COUNTRY") ?: "-"
        val cachedUrlScanUuid = intent.getStringExtra("HISTORY_URLSCAN_UUID") ?: "-"
        val cachedUrlScanScreenshotUrl =
            intent.getStringExtra("HISTORY_URLSCAN_SCREENSHOT_URL") ?: "-"

        currentRiskLabel = cachedLabel
        btnOpenLink.isEnabled = true

        currentRedirectChain = cachedRedirectChain

        currentUrlScanStatus = cachedUrlScanStatus
        currentUrlScanDetails = cachedUrlScanDetails
        currentUrlScanDomain = cachedUrlScanDomain
        currentUrlScanIp = cachedUrlScanIp
        currentUrlScanCountry = cachedUrlScanCountry
        currentUrlScanUuid = cachedUrlScanUuid
        currentUrlScanScreenshotUrl = cachedUrlScanScreenshotUrl

        tvScanInfo.text = "Previous scan history\n$cachedDate"
        tvValidation.text = cachedValidation
        tvRedirectChain.text = cachedRedirectChain

        tvUrlMetadata.text = """
Domain: $cachedUrlScanDomain
IP Address: $cachedUrlScanIp
Country: $cachedUrlScanCountry
UUID: $cachedUrlScanUuid
        """.trimIndent()

        tvCharacteristics.text = cachedCharacteristics

        tvVirusTotalStatus.text = cachedVtStatus
        tvVirusTotalDetails.text = cachedVtDetails

        tvSafeBrowsingStatus.text = cachedSbStatus
        tvSafeBrowsingDetails.text = cachedSbDetails

        tvUrlScanStatus.text = cachedUrlScanStatus
        tvUrlScanDetails.text = cachedUrlScanDetails

        tvRiskLabel.text = cachedLabel
        tvRiskScore.text = "Score: $cachedScore/100"
        findViewById<TextView>(R.id.tvScoreGuide).text =
            "ⓘ Score band: ${getScoreBandLabel(cachedScore, cachedLabel)}. Tap for guide."
        progressRisk.progress = cachedScore
        tvConfidence.text = "Confidence: Loaded from previous scan"
        tvRiskReason.text = cachedRiskReason

        val riskColor = when (cachedLabel) {
            "SAFE" -> Color.parseColor("#4CAF50")
            "SUSPICIOUS" -> Color.parseColor("#FFC107")
            "MALICIOUS" -> Color.parseColor("#F44336")
            else -> Color.GRAY
        }

        tvRiskLabel.setTextColor(riskColor)
        progressRisk.progressTintList = ColorStateList.valueOf(riskColor)

        when (cachedVtStatus) {
            "Malicious" -> tvVirusTotalStatus.setTextColor(Color.parseColor("#F44336"))
            "Suspicious" -> tvVirusTotalStatus.setTextColor(Color.parseColor("#FFC107"))
            "Clean" -> tvVirusTotalStatus.setTextColor(Color.parseColor("#4CAF50"))
            else -> tvVirusTotalStatus.setTextColor(Color.GRAY)
        }

        when (cachedSbStatus) {
            "Threat Found" -> tvSafeBrowsingStatus.setTextColor(Color.parseColor("#F44336"))
            "Clean" -> tvSafeBrowsingStatus.setTextColor(Color.parseColor("#4CAF50"))
            else -> tvSafeBrowsingStatus.setTextColor(Color.GRAY)
        }

        when (cachedUrlScanStatus) {
            "Malicious" -> tvUrlScanStatus.setTextColor(Color.parseColor("#F44336"))
            "Suspicious" -> tvUrlScanStatus.setTextColor(Color.parseColor("#FFC107"))
            "Clean" -> tvUrlScanStatus.setTextColor(Color.parseColor("#4CAF50"))
            else -> tvUrlScanStatus.setTextColor(Color.GRAY)
        }

        loadScreenshotPreview(
            imageView = ivUrlScanScreenshot,
            hintView = tvScreenshotHint,
            screenshotUrl = cachedUrlScanScreenshotUrl
        )
    }

    private fun getVirusTotalFromIntent(): VirusTotalClient.VirusTotalStats? {
        val vtStatus = intent.getStringExtra("VT_STATUS")

        return if (vtStatus == "SUCCESS") {
            VirusTotalClient.VirusTotalStats(
                malicious = intent.getIntExtra("VT_MALICIOUS", 0),
                suspicious = intent.getIntExtra("VT_SUSPICIOUS", 0),
                harmless = intent.getIntExtra("VT_HARMLESS", 0),
                undetected = intent.getIntExtra("VT_UNDETECTED", 0)
            )
        } else {
            null
        }
    }

    private fun updateVirusTotalFromLoadingIntent(
        statusView: TextView,
        detailsView: TextView
    ) {
        val vtStatus = intent.getStringExtra("VT_STATUS") ?: "NOT_AVAILABLE"
        virusTotalCheckStatus = vtStatus

        when (vtStatus) {
            "SUCCESS" -> updateVirusTotalUI(statusView, detailsView)

            "FAILED" -> {
                statusView.text = "Failed"
                statusView.setTextColor(Color.GRAY)
                detailsView.text =
                    "VirusTotal check failed during loading screen. Safe status cannot be fully confirmed."
            }

            "TIMEOUT" -> {
                statusView.text = "Timeout"
                statusView.setTextColor(Color.GRAY)
                detailsView.text =
                    "VirusTotal did not respond within the allowed waiting time. Safe status cannot be fully confirmed."
            }

            else -> {
                statusView.text = "Not Available"
                statusView.setTextColor(Color.GRAY)
                detailsView.text =
                    "VirusTotal result was not passed from loading screen. Safe status cannot be fully confirmed."
            }
        }
    }

    private fun loadSafeBrowsingFromIntent(
        statusView: TextView,
        detailsView: TextView
    ) {
        val sbStatus = intent.getStringExtra("SB_STATUS") ?: "FAILED"
        safeBrowsingCheckStatus = sbStatus
        val sbHasThreat = intent.getBooleanExtra("SB_HAS_THREAT", false)
        val sbThreatTypesText = intent.getStringExtra("SB_THREAT_TYPES") ?: ""

        safeBrowsingFinished = true

        if (sbStatus == "SUCCESS") {
            val threatTypes = if (sbThreatTypesText.isBlank()) {
                emptyList()
            } else {
                sbThreatTypesText.split(",").map { it.trim() }
            }

            sbResult = SafeBrowsingClient.SafeBrowsingResult(
                hasThreat = sbHasThreat,
                threatTypes = threatTypes
            )

            updateSafeBrowsingUI(statusView, detailsView)

        } else {
            sbResult = null
            statusView.text = sbStatus
            statusView.setTextColor(Color.GRAY)
            detailsView.text =
                "Google Safe Browsing check did not complete successfully. Safe status cannot be fully confirmed."
        }
    }

    private fun loadUrlScanFromIntent(
        statusView: TextView,
        detailsView: TextView,
        metadataView: TextView,
        imageView: ImageView,
        hintView: TextView
    ) {
        urlScanCheckStatus = intent.getStringExtra("URLSCAN_STATUS") ?: "NOT_AVAILABLE"
        val urlScanVerdict = intent.getStringExtra("URLSCAN_VERDICT") ?: "Not Available"
        val urlScanDetails = intent.getStringExtra("URLSCAN_DETAILS")
            ?: "urlscan.io result not available."

        val urlScanDomain = intent.getStringExtra("URLSCAN_DOMAIN") ?: "-"
        val urlScanIp = intent.getStringExtra("URLSCAN_IP") ?: "-"
        val urlScanCountry = intent.getStringExtra("URLSCAN_COUNTRY") ?: "-"
        val urlScanUuid = intent.getStringExtra("URLSCAN_UUID") ?: "-"
        val urlScanScreenshotUrl = intent.getStringExtra("URLSCAN_SCREENSHOT_URL") ?: "-"

        currentUrlScanStatus = urlScanVerdict
        currentUrlScanDetails = urlScanDetails
        currentUrlScanDomain = urlScanDomain
        currentUrlScanIp = urlScanIp
        currentUrlScanCountry = urlScanCountry
        currentUrlScanUuid = urlScanUuid
        currentUrlScanScreenshotUrl = urlScanScreenshotUrl

        statusView.text = urlScanVerdict

        when (urlScanVerdict) {
            "Malicious" -> statusView.setTextColor(Color.parseColor("#F44336"))
            "Suspicious" -> statusView.setTextColor(Color.parseColor("#FFC107"))
            "Clean" -> statusView.setTextColor(Color.parseColor("#4CAF50"))
            else -> statusView.setTextColor(Color.GRAY)
        }

        detailsView.text = urlScanDetails

        metadataView.text = """
Domain: $urlScanDomain
IP Address: $urlScanIp
Country: $urlScanCountry
UUID: $urlScanUuid
        """.trimIndent()

        loadScreenshotPreview(
            imageView = imageView,
            hintView = hintView,
            screenshotUrl = urlScanScreenshotUrl
        )
    }

    private fun updateCharacteristics(tvCharacteristics: TextView) {
        tvCharacteristics.text = if (ruleFindings.isEmpty()) {
            "No suspicious characteristics detected"
        } else {
            ruleFindings.joinToString(separator = "\n") {
                "• ${it.message} (${formatScore(it.score)})"
            }
        }
    }

    private fun checkRedirectsInBackground(
        url: String,
        tvCharacteristics: TextView,
        tvRedirectChain: TextView,
        tvRiskLabel: TextView,
        tvRiskScore: TextView,
        progressRisk: ProgressBar,
        tvConfidence: TextView,
        tvRiskReason: TextView
    ) {
        Thread {
            val redirectUrls = getRedirectChain(url)

            runOnUiThread {
                val redirectCount = if (redirectUrls.isNotEmpty()) {
                    redirectUrls.size - 1
                } else {
                    0
                }

                currentRedirectChain = buildRedirectChainText(redirectUrls)
                tvRedirectChain.text = currentRedirectChain

                when {
                    redirectCount >= 4 -> {
                        addFindingIfMissing(
                            "Redirection chain ≥ 4 redirects (high-risk indicator): $redirectCount redirects",
                            40
                        )
                    }

                    redirectCount >= 2 -> {
                        addFindingIfMissing(
                            "Redirection chain has 2–3 redirects (suspicious indicator): $redirectCount redirects",
                            15
                        )
                    }

                    redirectCount == 1 -> {
                        addFindingIfMissing(
                            "Single redirect detected: $redirectCount redirect",
                            5
                        )
                    }
                }

                redirectFinished = true
                updateCharacteristics(tvCharacteristics)

                updateFinalRiskUI(
                    tvRiskLabel,
                    tvRiskScore,
                    progressRisk,
                    tvConfidence,
                    tvRiskReason
                )
            }
        }.start()
    }

    private fun getRedirectChain(url: String, maxRedirects: Int = 10): List<String> {
        val redirectChain = mutableListOf<String>()
        var currentUrl = url

        redirectChain.add(currentUrl)

        val client = OkHttpClient.Builder()
            .followRedirects(false)
            .followSslRedirects(false)
            .connectTimeout(8, TimeUnit.SECONDS)
            .readTimeout(8, TimeUnit.SECONDS)
            .writeTimeout(8, TimeUnit.SECONDS)
            .build()

        try {
            while (redirectChain.size <= maxRedirects) {
                val request = Request.Builder()
                    .url(currentUrl)
                    .header("User-Agent", "SecureQRScanner/1.0")
                    .build()

                val response = client.newCall(request).execute()
                val location = response.header("Location")

                if (response.code in 300..399 && !location.isNullOrBlank()) {
                    currentUrl =
                        if (location.startsWith("http://") || location.startsWith("https://")) {
                            location
                        } else {
                            val baseUri = URI(currentUrl)
                            baseUri.resolve(location).toString()
                        }

                    redirectChain.add(currentUrl)
                    response.close()
                } else {
                    response.close()
                    break
                }
            }
        } catch (e: Exception) {
            if (redirectChain.isEmpty()) {
                redirectChain.add(url)
            }
        }

        return redirectChain
    }

    private fun buildRedirectChainText(redirectUrls: List<String>): String {
        if (redirectUrls.isEmpty()) {
            return "No redirect information available"
        }

        val redirectCount = redirectUrls.size - 1

        if (redirectCount == 0) {
            return """
Total redirects: 0

1. Original URL:
${redirectUrls[0]}
            """.trimIndent()
        }

        val builder = StringBuilder()
        builder.append("Total redirects: $redirectCount\n\n")

        redirectUrls.forEachIndexed { index, redirectUrl ->
            if (index == 0) {
                builder.append("${index + 1}. Original URL:\n")
            } else {
                builder.append("${index + 1}. Redirect $index:\n")
            }

            builder.append(redirectUrl)
            builder.append("\n\n")
        }

        return builder.toString().trim()
    }

    private fun addFindingIfMissing(message: String, score: Int) {
        val exists = ruleFindings.any { it.message == message }

        if (!exists) {
            ruleFindings.add(RuleFinding(message, score))
        }
    }

    private fun updateVirusTotalUI(statusView: TextView, detailsView: TextView) {
        val stats = vtStats

        if (stats != null) {
            when {
                stats.malicious > 0 -> {
                    statusView.text = "Malicious"
                    statusView.setTextColor(Color.parseColor("#F44336"))
                }

                stats.suspicious > 0 -> {
                    statusView.text = "Suspicious"
                    statusView.setTextColor(Color.parseColor("#FFC107"))
                }

                else -> {
                    statusView.text = "Clean"
                    statusView.setTextColor(Color.parseColor("#4CAF50"))
                }
            }

            detailsView.text = """
• Malicious: ${stats.malicious}
• Suspicious: ${stats.suspicious}
• Harmless: ${stats.harmless}
• Undetected: ${stats.undetected}
            """.trimIndent()
        } else {
            statusView.text = "Failed"
            statusView.setTextColor(Color.GRAY)
            detailsView.text = "Could not retrieve VirusTotal result"
        }
    }

    private fun updateSafeBrowsingUI(statusView: TextView, detailsView: TextView) {
        val result = sbResult

        if (result != null) {
            if (result.hasThreat) {
                statusView.text = "Threat Found"
                statusView.setTextColor(Color.parseColor("#F44336"))

                detailsView.text = buildString {
                    result.threatTypes.forEach {
                        append("• $it\n")
                    }
                }.trim()
            } else {
                statusView.text = "Clean"
                statusView.setTextColor(Color.parseColor("#4CAF50"))
                detailsView.text = "• No threat found"
            }
        } else {
            statusView.text = "Failed"
            statusView.setTextColor(Color.GRAY)
            detailsView.text = "Could not retrieve Safe Browsing result"
        }
    }

    private fun updateFinalRiskUI(
        tvRiskLabel: TextView,
        tvRiskScore: TextView,
        progressRisk: ProgressBar,
        tvConfidence: TextView,
        tvRiskReason: TextView
    ) {
        val score = calculateRiskScore()
        val finalLabel = getCombinedRiskLabel(score, vtStats, sbResult)
        val confidence = getConfidenceLabel(score, vtStats, sbResult)
        val reason = buildRiskReason(score, finalLabel)

        currentRiskLabel = finalLabel

        tvRiskLabel.text = finalLabel
        tvRiskScore.text = "Score: $score/100"
        findViewById<TextView>(R.id.tvScoreGuide).text =
            "ⓘ Score band: ${getScoreBandLabel(score, finalLabel)}. Tap for guide."
        progressRisk.progress = score
        tvConfidence.text = "Confidence: $confidence"
        tvRiskReason.text = reason

        val color = when (finalLabel) {
            "SAFE" -> Color.parseColor("#4CAF50")
            "SUSPICIOUS" -> Color.parseColor("#FFC107")
            "MALICIOUS" -> Color.parseColor("#F44336")
            "UNKNOWN" -> Color.GRAY
            else -> Color.WHITE
        }

        tvRiskLabel.setTextColor(color)
        progressRisk.progressTintList = ColorStateList.valueOf(color)

        saveHistoryOnce(finalLabel, score)
    }

    private fun calculateRiskScore(): Int {
        if (sbResult?.hasThreat == true) return 100
        if (vtStats != null && vtStats!!.malicious > 0) return 100

        var score = ruleFindings.sumOf { it.score }

        if (vtStats != null && vtStats!!.suspicious > 0) {
            score += 30
        }

        return score.coerceIn(0, 100)
    }

    private fun getCombinedRiskLabel(
        score: Int,
        vtStats: VirusTotalClient.VirusTotalStats?,
        sbResult: SafeBrowsingClient.SafeBrowsingResult?
    ): String {
        if (sbResult?.hasThreat == true) return "MALICIOUS"
        if (vtStats != null && vtStats.malicious > 0) return "MALICIOUS"

        if ((vtStats != null && vtStats.suspicious > 0) || score >= 40) {
            return "SUSPICIOUS"
        }

        if (vtStats != null && sbResult != null && !sbResult.hasThreat &&
            vtStats.malicious == 0 && vtStats.suspicious == 0 && score < 40
        ) {
            return "SAFE"
        }

        return if (score >= 40) "SUSPICIOUS" else "UNKNOWN"
    }

    private fun getConfidenceLabel(
        score: Int,
        vtStats: VirusTotalClient.VirusTotalStats?,
        sbResult: SafeBrowsingClient.SafeBrowsingResult?
    ): String {
        return when {
            sbResult?.hasThreat == true -> "High - Google Safe Browsing confirmed threat"
            vtStats != null && vtStats.malicious > 0 -> "High - VirusTotal confirmed malicious detection"
            vtStats != null && vtStats.suspicious > 0 -> "Medium - VirusTotal reported suspicious detection"
            hasPrimaryApiFailure() && score >= 40 -> "Low - API unavailable; rule-based warning only"
            hasPrimaryApiFailure() -> "Low - API unavailable; safe status cannot be confirmed"
            score >= 70 -> "Medium - high rule-based score"
            score >= 40 -> "Low - rule-based indicators only"
            hasUrlScanFailure() -> "Medium - primary APIs clean; urlscan.io evidence unavailable"
            else -> "Medium - APIs clean and rule score low"
        }
    }

    private fun hasPrimaryApiFailure(): Boolean {
        return virusTotalCheckStatus != "SUCCESS" || safeBrowsingCheckStatus != "SUCCESS"
    }

    private fun hasUrlScanFailure(): Boolean {
        return urlScanCheckStatus != "Completed"
    }

    private fun getScoreBandLabel(score: Int, finalLabel: String): String {
        return when {
            finalLabel == "MALICIOUS" || score >= 100 -> "100 API-confirmed malicious"
            score >= 70 -> "70-99 high suspicious"
            score >= 40 -> "40-69 suspicious"
            score >= 20 -> "20-39 low suspicious"
            else -> "0-19 low concern"
        }
    }

    private fun formatScore(score: Int): String {
        return if (score > 0) "+$score" else score.toString()
    }

    private fun buildRiskReason(score: Int, finalLabel: String): String {
        val reasons = mutableListOf<String>()
        val positiveFindings = ruleFindings.filter { it.score > 0 }
        val scoreAdjustments = ruleFindings.filter { it.score < 0 }

        if (sbResult?.hasThreat == true) {
            reasons.add("Google Safe Browsing detected a known unsafe URL.")
        }

        if (vtStats != null && vtStats!!.malicious > 0) {
            reasons.add("VirusTotal reported ${vtStats!!.malicious} malicious detection(s).")
        }

        if (vtStats != null && vtStats!!.suspicious > 0) {
            reasons.add("VirusTotal reported ${vtStats!!.suspicious} suspicious detection(s).")
        }

        if (hasPrimaryApiFailure()) {
            reasons.add(
                "One or more primary API checks were unavailable, so safe status cannot be fully confirmed."
            )
        }

        if (positiveFindings.isNotEmpty()) {
            reasons.add("Rule-based analysis found ${positiveFindings.size} suspicious characteristic(s).")

            val topFindings = positiveFindings
                .sortedByDescending { it.score }
                .take(3)

            topFindings.forEach {
                reasons.add("${it.message} (${formatScore(it.score)})")
            }
        }

        scoreAdjustments.forEach {
            reasons.add("${it.message} (${formatScore(it.score)})")
        }

        if (reasons.isEmpty()) {
            reasons.add("No suspicious rule-based indicators were found.")
            reasons.add("No threat was confirmed by the available API results.")
        }

        reasons.add("Final decision: $finalLabel with score $score/100.")

        return reasons.joinToString(separator = "\n") { "• $it" }
    }

    private fun saveHistoryOnce(riskLabel: String, score: Int) {
        if (hasSavedHistory) return
        if (!safeBrowsingFinished) return
        if (!redirectFinished) return

        if (riskLabel == "CHECKING..." || riskLabel == "UNKNOWN" || riskLabel == "INVALID") {
            return
        }

        val tvValidation = findViewById<TextView>(R.id.tvValidation)
        val tvCharacteristics = findViewById<TextView>(R.id.tvCharacteristics)
        val tvRiskReason = findViewById<TextView>(R.id.tvRiskReason)
        val tvRedirectChain = findViewById<TextView>(R.id.tvRedirectChain)

        val tvVirusTotalStatus = findViewById<TextView>(R.id.tvVirusTotalStatus)
        val tvVirusTotalDetails = findViewById<TextView>(R.id.tvVirusTotalDetails)

        val tvSafeBrowsingStatus = findViewById<TextView>(R.id.tvSafeBrowsingStatus)
        val tvSafeBrowsingDetails = findViewById<TextView>(R.id.tvSafeBrowsingDetails)

        ScanHistoryManager.saveScan(
            context = this,
            url = scannedUrl,
            riskLabel = riskLabel,
            riskScore = score,
            scannedAt = currentScanTime,
            validation = tvValidation.text.toString(),
            characteristics = tvCharacteristics.text.toString(),
            riskReason = tvRiskReason.text.toString(),
            redirectChain = tvRedirectChain.text.toString(),
            virusTotalStatus = tvVirusTotalStatus.text.toString(),
            virusTotalDetails = tvVirusTotalDetails.text.toString(),
            safeBrowsingStatus = tvSafeBrowsingStatus.text.toString(),
            safeBrowsingDetails = tvSafeBrowsingDetails.text.toString(),
            urlScanStatus = currentUrlScanStatus,
            urlScanDetails = currentUrlScanDetails,
            urlScanDomain = currentUrlScanDomain,
            urlScanIp = currentUrlScanIp,
            urlScanCountry = currentUrlScanCountry,
            urlScanUuid = currentUrlScanUuid,
            urlScanScreenshotUrl = currentUrlScanScreenshotUrl
        )

        hasSavedHistory = true
    }

    private fun isValidWebUrl(text: String): Boolean {
        return Patterns.WEB_URL.matcher(text).matches()
    }

    private fun analyzeUrlStatic(url: String): List<RuleFinding> {
        val findings = mutableListOf<RuleFinding>()

        try {
            val uri = URI(url)
            val host = uri.host ?: ""
            val scheme = uri.scheme ?: ""
            val fullUrlLower = url.lowercase()

            if (url.length > 75) {
                findings.add(RuleFinding("URL length > 75 characters (high-risk indicator)", 20))
            } else if (url.length in 54..75) {
                findings.add(RuleFinding("URL length between 54–75 characters (suspicious indicator)", 10))
            }

            val cleanedHost = host.removePrefix("www.").lowercase()
            val dotCount = cleanedHost.count { it == '.' }
            val trustedDomain = isTrustedDomain(cleanedHost)

            if (dotCount >= 4) {
                findings.add(
                    RuleFinding(
                        "Domain contains ≥ 4 dots / multiple subdomains (high-risk indicator)",
                        20
                    )
                )
            } else if (dotCount == 3) {
                findings.add(
                    RuleFinding(
                        "Domain contains 3 dots / several subdomains (suspicious indicator)",
                        10
                    )
                )
            }

            if (scheme.lowercase() == "http") {
                findings.add(RuleFinding("Uses HTTP instead of HTTPS", 10))
            }

            if (isShortenedUrl(cleanedHost)) {
                findings.add(RuleFinding("Shortened URL detected", 20))
            }

            if (isIpAddress(cleanedHost)) {
                findings.add(RuleFinding("Uses IP address instead of domain name", 25))
            }

            if (hasSuspiciousTld(cleanedHost)) {
                findings.add(RuleFinding("Suspicious top-level domain detected", 15))
            }

            if (url.contains("@")) {
                findings.add(
                    RuleFinding(
                        "URL contains '@' symbol, which may hide the real destination",
                        20
                    )
                )
            }

            findings.addAll(detectPhishingKeywords(fullUrlLower))

            val positiveScore = findings.sumOf { if (it.score > 0) it.score else 0 }
            if (trustedDomain && positiveScore > 0) {
                findings.add(
                    RuleFinding(
                        "Trusted domain match reduces weak lexical false positives",
                        -15
                    )
                )
            }

        } catch (e: Exception) {
            findings.add(RuleFinding("Unable to analyze URL structure", 5))
        }

        return findings
    }

    private fun isShortenedUrl(host: String): Boolean {
        val shorteners = listOf(
            "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
            "is.gd", "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at",
            "s.id", "rb.gy", "lnkd.in"
        )

        return shorteners.any { host.equals(it, ignoreCase = true) }
    }

    private fun isTrustedDomain(host: String): Boolean {
        val trustedDomains = listOf(
            "google.com",
            "microsoft.com",
            "live.com",
            "office.com",
            "apple.com",
            "icloud.com",
            "paypal.com",
            "maybank2u.com.my",
            "cimbclicks.com.my",
            "publicbank.com.my",
            "rhbgroup.com",
            "touchngo.com.my",
            "unikl.edu.my"
        )

        return trustedDomains.any { domain ->
            host == domain || host.endsWith(".$domain")
        }
    }

    private fun isIpAddress(host: String): Boolean {
        val ipRegex = Regex("""^(\d{1,3}\.){3}\d{1,3}$""")
        return ipRegex.matches(host)
    }

    private fun hasSuspiciousTld(host: String): Boolean {
        val suspiciousTlds = listOf(
            ".xyz", ".tk", ".top", ".club", ".click", ".buzz", ".gq", ".cf", ".ml"
        )

        return suspiciousTlds.any { host.lowercase().endsWith(it) }
    }

    private fun detectPhishingKeywords(url: String): List<RuleFinding> {
        val findings = mutableListOf<RuleFinding>()

        val suspiciousKeywords = listOf(
            "login", "verify", "password", "reset",
            "bank", "secure", "update", "account",
            "otp", "wallet", "invoice", "confirm", "signin"
        )

        var keywordScore = 0

        for (keyword in suspiciousKeywords) {
            if (url.contains(keyword)) {
                if (keywordScore < 30) {
                    findings.add(RuleFinding("Suspicious keyword detected: $keyword", 10))
                    keywordScore += 10
                } else {
                    findings.add(
                        RuleFinding(
                            "Additional suspicious keyword detected but keyword score capped: $keyword",
                            0
                        )
                    )
                }
            }
        }

        return findings
    }

    private fun showScoreGuideDialog() {
        AlertDialog.Builder(this)
            .setTitle("Risk Score Guide")
            .setMessage(
                """
0-19: Low concern
20-39: Low suspicious indicators
40-69: Suspicious
70-99: High suspicious
100: Malicious only when confirmed by API

Rule-based scoring is used as an early warning layer. Google Safe Browsing or VirusTotal confirmation is required before the app labels a URL as malicious.

If an API check fails or times out, the app lowers confidence and avoids marking the URL as fully safe.
                """.trimIndent()
            )
            .setPositiveButton("OK", null)
            .show()
    }

    private fun showWarningDialog(riskLabel: String, url: String) {
        val dialog = AlertDialog.Builder(this)
            .setTitle("Warning: $riskLabel URL")
            .setMessage(
                "This link may be unsafe based on the scan result.\n\n" +
                        "Opening it could expose you to phishing, malware, or data theft.\n\n" +
                        "URL:\n$url"
            )
            .setPositiveButton("Open Anyway", null)
            .setNegativeButton("Cancel") { d, _ -> d.dismiss() }
            .create()

        dialog.setOnShowListener {
            val openButton = dialog.getButton(AlertDialog.BUTTON_POSITIVE)
            openButton.isEnabled = false

            object : CountDownTimer(5000, 1000) {
                override fun onTick(millisUntilFinished: Long) {
                    val secondsLeft = millisUntilFinished / 1000
                    openButton.text = "Open Anyway (${secondsLeft}s)"
                }

                override fun onFinish() {
                    openButton.text = "Open Anyway"
                    openButton.isEnabled = true

                    openButton.setOnClickListener {
                        dialog.dismiss()
                        openUrl(url)
                    }
                }
            }.start()
        }

        dialog.show()
    }

    private fun openUrl(url: String) {
        try {
            val intent = Intent(Intent.ACTION_VIEW, Uri.parse(url))
            startActivity(intent)
        } catch (e: Exception) {
            Toast.makeText(this, "Unable to open link", Toast.LENGTH_SHORT).show()
        }
    }

    private fun loadScreenshotPreview(
        imageView: ImageView,
        hintView: TextView,
        screenshotUrl: String
    ) {
        if (screenshotUrl.isBlank() || screenshotUrl == "-") {
            showScreenshotMessage(imageView, hintView, "Screenshot not available")
            return
        }

        hintView.text = "Preparing screenshot preview..."

        downloadScreenshotWithRetry(
            imageView = imageView,
            hintView = hintView,
            screenshotUrl = screenshotUrl,
            attempt = 1
        )
    }

    private fun downloadScreenshotWithRetry(
        imageView: ImageView,
        hintView: TextView,
        screenshotUrl: String,
        attempt: Int
    ) {
        val maxAttempts = 8

        Thread {
            try {
                val client = OkHttpClient.Builder()
                    .connectTimeout(10, TimeUnit.SECONDS)
                    .readTimeout(15, TimeUnit.SECONDS)
                    .build()

                val request = Request.Builder()
                    .url(screenshotUrl)
                    .header("User-Agent", "Mozilla/5.0")
                    .get()
                    .build()

                val response = client.newCall(request).execute()

                response.use {
                    val contentType = it.header("Content-Type")?.lowercase() ?: ""
                    val bytes = it.body?.bytes()

                    val bitmap: Bitmap? =
                        if (
                            it.isSuccessful &&
                            contentType.contains("image") &&
                            bytes != null &&
                            bytes.isNotEmpty()
                        ) {
                            BitmapFactory.decodeByteArray(bytes, 0, bytes.size)
                        } else {
                            null
                        }

                    runOnUiThread {
                        if (bitmap != null) {
                            currentScreenshotBitmap = bitmap

                            imageView.setImageBitmap(bitmap)
                            hintView.text = "Tap screenshot to open zoom view"

                            imageView.setOnClickListener {
                                showScreenshotZoomDialog(bitmap)
                            }
                        } else {
                            retryScreenshotDownload(
                                imageView = imageView,
                                hintView = hintView,
                                screenshotUrl = screenshotUrl,
                                attempt = attempt,
                                maxAttempts = maxAttempts
                            )
                        }
                    }
                }

            } catch (e: Exception) {
                runOnUiThread {
                    retryScreenshotDownload(
                        imageView = imageView,
                        hintView = hintView,
                        screenshotUrl = screenshotUrl,
                        attempt = attempt,
                        maxAttempts = maxAttempts
                    )
                }
            }
        }.start()
    }

    private fun retryScreenshotDownload(
        imageView: ImageView,
        hintView: TextView,
        screenshotUrl: String,
        attempt: Int,
        maxAttempts: Int
    ) {
        if (attempt >= maxAttempts) {
            showScreenshotMessage(
                imageView = imageView,
                hintView = hintView,
                message = "Screenshot preview not ready yet"
            )
            return
        }

        hintView.text = "Waiting for screenshot... attempt $attempt/$maxAttempts"

        imageView.postDelayed({
            downloadScreenshotWithRetry(
                imageView = imageView,
                hintView = hintView,
                screenshotUrl = screenshotUrl,
                attempt = attempt + 1
            )
        }, 3000)
    }

    private fun showScreenshotMessage(
        imageView: ImageView,
        hintView: TextView,
        message: String
    ) {
        imageView.setImageDrawable(null)
        imageView.setBackgroundColor(Color.parseColor("#0F1115"))
        hintView.text = message
    }

    private fun showScreenshotZoomDialog(bitmap: Bitmap) {
        val imageView = ImageView(this).apply {
            setImageBitmap(bitmap)
            scaleType = ImageView.ScaleType.MATRIX
            setBackgroundColor(Color.BLACK)
            adjustViewBounds = true
        }

        val matrix = Matrix()
        val savedMatrix = Matrix()

        var lastX = 0f
        var lastY = 0f
        var mode = 0

        val scaleGestureDetector = ScaleGestureDetector(
            this,
            object : ScaleGestureDetector.SimpleOnScaleGestureListener() {
                override fun onScale(detector: ScaleGestureDetector): Boolean {
                    val scale = detector.scaleFactor

                    matrix.postScale(
                        scale,
                        scale,
                        detector.focusX,
                        detector.focusY
                    )

                    imageView.imageMatrix = matrix
                    return true
                }
            }
        )

        imageView.setOnTouchListener { _, event ->
            scaleGestureDetector.onTouchEvent(event)

            when (event.actionMasked) {
                MotionEvent.ACTION_DOWN -> {
                    savedMatrix.set(matrix)
                    lastX = event.x
                    lastY = event.y
                    mode = 1
                }

                MotionEvent.ACTION_MOVE -> {
                    if (mode == 1 && !scaleGestureDetector.isInProgress) {
                        val dx = event.x - lastX
                        val dy = event.y - lastY

                        matrix.set(savedMatrix)
                        matrix.postTranslate(dx, dy)

                        imageView.imageMatrix = matrix
                    }
                }

                MotionEvent.ACTION_UP,
                MotionEvent.ACTION_POINTER_UP -> {
                    mode = 0
                }
            }

            true
        }

        val container = FrameLayout(this).apply {
            setBackgroundColor(Color.BLACK)
            addView(
                imageView,
                FrameLayout.LayoutParams(
                    FrameLayout.LayoutParams.MATCH_PARENT,
                    FrameLayout.LayoutParams.MATCH_PARENT
                )
            )
        }

        val dialog = AlertDialog.Builder(this)
            .setTitle("Website Screenshot")
            .setView(container)
            .setPositiveButton("Close", null)
            .create()

        dialog.setOnShowListener {
            val width = (resources.displayMetrics.widthPixels * 0.95).toInt()
            val height = (resources.displayMetrics.heightPixels * 0.75).toInt()

            dialog.window?.setLayout(width, height)
        }

        dialog.show()
    }

    private fun createAndSharePdfReport(
        tvRiskLabel: TextView,
        tvRiskScore: TextView,
        tvConfidence: TextView,
        tvScannedUrl: TextView,
        tvScanInfo: TextView,
        tvValidation: TextView,
        tvUrlMetadata: TextView,
        tvRedirectChain: TextView,
        tvRiskReason: TextView,
        tvCharacteristics: TextView,
        tvVirusTotalStatus: TextView,
        tvVirusTotalDetails: TextView,
        tvSafeBrowsingStatus: TextView,
        tvSafeBrowsingDetails: TextView,
        tvUrlScanStatus: TextView,
        tvUrlScanDetails: TextView
    ) {
        try {
            val pdfDocument = PdfDocument()

            val pageWidth = 595
            val pageHeight = 842
            val margin = 40

            var pageNumber = 1
            var y = 50

            var pageInfo = PdfDocument.PageInfo.Builder(pageWidth, pageHeight, pageNumber).create()
            var page = pdfDocument.startPage(pageInfo)
            var canvas = page.canvas

            val titlePaint = Paint().apply {
                textSize = 22f
                isFakeBoldText = true
                color = Color.BLACK
            }

            val subtitlePaint = Paint().apply {
                textSize = 11f
                color = Color.DKGRAY
            }

            val sectionTitlePaint = Paint().apply {
                textSize = 14f
                isFakeBoldText = true
                color = Color.BLACK
            }

            val labelPaint = Paint().apply {
                textSize = 10.5f
                isFakeBoldText = true
                color = Color.DKGRAY
            }

            val bodyPaint = Paint().apply {
                textSize = 10.5f
                color = Color.BLACK
            }

            val smallPaint = Paint().apply {
                textSize = 9.5f
                color = Color.DKGRAY
            }

            val whiteBoldPaint = Paint().apply {
                textSize = 13f
                isFakeBoldText = true
                color = Color.WHITE
                textAlign = Paint.Align.CENTER
            }

            fun riskColor(label: String): Int {
                return when (label.uppercase()) {
                    "SAFE" -> Color.rgb(46, 125, 50)
                    "SUSPICIOUS" -> Color.rgb(245, 124, 0)
                    "MALICIOUS" -> Color.rgb(198, 40, 40)
                    else -> Color.rgb(97, 97, 97)
                }
            }

            fun drawFooter() {
                val footerPaint = Paint().apply {
                    textSize = 9f
                    color = Color.GRAY
                    textAlign = Paint.Align.CENTER
                }

                canvas.drawText(
                    "Secure QR Scanner Report • Page $pageNumber",
                    (pageWidth / 2).toFloat(),
                    (pageHeight - 25).toFloat(),
                    footerPaint
                )
            }

            fun startNewPage() {
                drawFooter()
                pdfDocument.finishPage(page)

                pageNumber++
                y = 50

                pageInfo = PdfDocument.PageInfo.Builder(pageWidth, pageHeight, pageNumber).create()
                page = pdfDocument.startPage(pageInfo)
                canvas = page.canvas
            }

            fun checkSpace(required: Int) {
                if (y + required > pageHeight - 60) {
                    startNewPage()
                }
            }

            fun drawWrappedText(
                text: String,
                paint: Paint = bodyPaint,
                x: Int = margin,
                maxChars: Int = 88,
                lineGap: Int = 16
            ) {
                val lines = wrapText(text, maxChars)

                for (line in lines) {
                    checkSpace(22)
                    canvas.drawText(line, x.toFloat(), y.toFloat(), paint)
                    y += lineGap
                }
            }

            fun drawSectionTitle(title: String) {
                checkSpace(45)
                y += 14
                canvas.drawText(title, margin.toFloat(), y.toFloat(), sectionTitlePaint)
                y += 12

                val linePaint = Paint().apply {
                    color = Color.rgb(210, 215, 222)
                    strokeWidth = 1.5f
                }

                canvas.drawLine(
                    margin.toFloat(),
                    y.toFloat(),
                    (pageWidth - margin).toFloat(),
                    y.toFloat(),
                    linePaint
                )

                y += 20
            }

            fun drawLabelValue(label: String, value: String) {
                checkSpace(24)
                canvas.drawText(label, margin.toFloat(), y.toFloat(), labelPaint)

                val cleanedValue = value.replace("\n", " ")
                val valueLines = wrapText(cleanedValue, 62)

                var firstLine = true

                for (line in valueLines) {
                    if (!firstLine) y += 15

                    canvas.drawText(
                        line,
                        (margin + 125).toFloat(),
                        y.toFloat(),
                        bodyPaint
                    )

                    firstLine = false
                }

                y += 20
            }

            fun drawMultilineBlock(text: String) {
                val rawLines = text.split("\n")

                for (line in rawLines) {
                    if (line.trim().isEmpty()) {
                        y += 8
                    } else {
                        drawWrappedText(line.trim(), bodyPaint, margin, 86)
                    }
                }
            }

            fun drawSmallNote(text: String) {
                drawWrappedText(text, smallPaint, margin, 90, 15)
            }

            canvas.drawText("Secure QR Scanner Report", margin.toFloat(), y.toFloat(), titlePaint)
            y += 18

            canvas.drawText(
                "Generated: ${getCurrentDateTime()}",
                margin.toFloat(),
                y.toFloat(),
                subtitlePaint
            )

            y += 28

            val riskLabel = tvRiskLabel.text.toString()
            val riskBadgeColor = riskColor(riskLabel)

            val badgeRect = RectF(
                margin.toFloat(),
                y.toFloat(),
                (pageWidth - margin).toFloat(),
                (y + 80).toFloat()
            )

            val badgePaint = Paint().apply {
                color = riskBadgeColor
            }

            canvas.drawRoundRect(badgeRect, 16f, 16f, badgePaint)

            val badgeTitlePaint = Paint().apply {
                textSize = 12f
                color = Color.WHITE
                textAlign = Paint.Align.CENTER
            }

            canvas.drawText(
                "FINAL RISK VERDICT",
                (pageWidth / 2).toFloat(),
                (y + 25).toFloat(),
                badgeTitlePaint
            )

            canvas.drawText(
                riskLabel,
                (pageWidth / 2).toFloat(),
                (y + 55).toFloat(),
                whiteBoldPaint
            )

            y += 105

            drawSectionTitle("1. Executive Summary")
            drawLabelValue("Risk Label", tvRiskLabel.text.toString())
            drawLabelValue("Risk Score", tvRiskScore.text.toString())
            drawLabelValue("Confidence", tvConfidence.text.toString())

            drawSectionTitle("2. Scan Information")
            drawLabelValue("Scanned URL", tvScannedUrl.text.toString())
            drawLabelValue("Scan Source", tvScanInfo.text.toString())
            drawLabelValue("Validation", tvValidation.text.toString())

            y += 4
            drawWrappedText("URL Metadata", labelPaint)
            y += 4
            drawMultilineBlock(tvUrlMetadata.text.toString())

            drawSectionTitle("3. Reason for Risk")
            drawMultilineBlock(tvRiskReason.text.toString())

            drawSectionTitle("4. Redirection Chain")
            drawMultilineBlock(tvRedirectChain.text.toString())

            drawSectionTitle("5. Detected URL Characteristics")
            drawMultilineBlock(tvCharacteristics.text.toString())

            drawSectionTitle("6. Threat Intelligence Results")
            drawLabelValue("VirusTotal", tvVirusTotalStatus.text.toString())
            drawMultilineBlock(tvVirusTotalDetails.text.toString())

            y += 8

            drawLabelValue("Google Safe Browsing", tvSafeBrowsingStatus.text.toString())
            drawMultilineBlock(tvSafeBrowsingDetails.text.toString())

            y += 8

            drawLabelValue("urlscan.io", tvUrlScanStatus.text.toString())
            drawMultilineBlock(tvUrlScanDetails.text.toString())

            y += 8
            drawLabelValue("Screenshot URL", currentUrlScanScreenshotUrl)

            drawSectionTitle("7. Disclaimer")
            drawSmallNote(
                "This report is generated by Secure QR Scanner as a security analysis summary. " +
                        "The result is based on rule-based URL analysis and available threat intelligence API responses at scan time. " +
                        "A safe result does not guarantee that the URL will remain safe in the future. " +
                        "Users are advised to avoid opening suspicious or malicious URLs unless they understand the risk."
            )

            drawFooter()
            pdfDocument.finishPage(page)

            val fileName = "SecureQR_Report_${System.currentTimeMillis()}.pdf"
            val file = File(cacheDir, fileName)

            val outputStream = FileOutputStream(file)
            pdfDocument.writeTo(outputStream)
            pdfDocument.close()
            outputStream.close()

            sharePdfFile(file)

        } catch (e: Exception) {
            Toast.makeText(
                this,
                "Failed: ${e.message}",
                Toast.LENGTH_LONG
            ).show()
        }
    }

    private fun sharePdfFile(file: File) {
        val uri = FileProvider.getUriForFile(
            this,
            "${packageName}.fileprovider",
            file
        )
        val readPermission = Intent.FLAG_GRANT_READ_URI_PERMISSION

        val shareIntent = Intent(Intent.ACTION_SEND).apply {
            type = "application/pdf"
            putExtra(Intent.EXTRA_STREAM, uri)
            clipData = ClipData.newUri(contentResolver, "Scan Report", uri)
            addFlags(readPermission)
        }

        packageManager.queryIntentActivities(shareIntent, 0).forEach { resolveInfo ->
            grantUriPermission(
                resolveInfo.activityInfo.packageName,
                uri,
                readPermission
            )
        }

        try {
            grantUriPermission("com.android.systemui", uri, readPermission)
        } catch (_: Exception) {
            // Some Android builds do not expose SystemUI as a grant target.
        }

        val chooser = Intent.createChooser(shareIntent, "Share Scan Report").apply {
            clipData = ClipData.newUri(contentResolver, "Scan Report", uri)
            addFlags(readPermission)
        }

        startActivity(chooser)
    }

    private fun getCurrentDateTime(): String {
        return SimpleDateFormat(
            "dd/MM/yyyy HH:mm",
            Locale.getDefault()
        ).format(Date())
    }

    private fun wrapText(text: String, maxChars: Int): List<String> {
        val result = mutableListOf<String>()
        val rawLines = text.split("\n")

        for (rawLine in rawLines) {
            if (rawLine.length <= maxChars) {
                result.add(rawLine)
            } else {
                var line = ""
                val words = rawLine.split(" ")

                for (word in words) {
                    if ((line + " " + word).trim().length > maxChars) {
                        result.add(line.trim())
                        line = word
                    } else {
                        line += " $word"
                    }
                }

                if (line.isNotBlank()) {
                    result.add(line.trim())
                }
            }
        }

        return result
    }
}
