package com.example.secureqrscanner

import android.app.AlertDialog
import android.content.Intent
import android.graphics.Color
import android.graphics.Typeface
import android.os.Bundle
import android.text.Editable
import android.text.TextWatcher
import android.view.View
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity

class HistoryActivity : AppCompatActivity() {

    private lateinit var historyContainer: LinearLayout
    private lateinit var tvEmptyHistory: TextView
    private lateinit var btnClearHistory: TextView
    private lateinit var etSearchHistory: EditText

    private lateinit var filterAll: TextView
    private lateinit var filterSafe: TextView
    private lateinit var filterSuspicious: TextView
    private lateinit var filterMalicious: TextView
    private lateinit var filterUnknown: TextView

    private var selectedFilter = "ALL"
    private var searchQuery = ""

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_history)

        historyContainer = findViewById(R.id.historyContainer)
        tvEmptyHistory = findViewById(R.id.tvEmptyHistory)
        btnClearHistory = findViewById(R.id.btnClearHistory)
        etSearchHistory = findViewById(R.id.etSearchHistory)

        filterAll = findViewById(R.id.filterAll)
        filterSafe = findViewById(R.id.filterSafe)
        filterSuspicious = findViewById(R.id.filterSuspicious)
        filterMalicious = findViewById(R.id.filterMalicious)
        filterUnknown = findViewById(R.id.filterUnknown)

        btnClearHistory.setOnClickListener {
            confirmClearHistory()
        }

        filterAll.setOnClickListener {
            selectedFilter = "ALL"
            updateFilterUi()
            loadHistoryList()
        }

        filterSafe.setOnClickListener {
            selectedFilter = "SAFE"
            updateFilterUi()
            loadHistoryList()
        }

        filterSuspicious.setOnClickListener {
            selectedFilter = "SUSPICIOUS"
            updateFilterUi()
            loadHistoryList()
        }

        filterMalicious.setOnClickListener {
            selectedFilter = "MALICIOUS"
            updateFilterUi()
            loadHistoryList()
        }

        filterUnknown.setOnClickListener {
            selectedFilter = "UNKNOWN"
            updateFilterUi()
            loadHistoryList()
        }

        etSearchHistory.addTextChangedListener(object : TextWatcher {
            override fun beforeTextChanged(
                s: CharSequence?,
                start: Int,
                count: Int,
                after: Int
            ) {
            }

            override fun onTextChanged(
                s: CharSequence?,
                start: Int,
                before: Int,
                count: Int
            ) {
                searchQuery = s?.toString()?.trim()?.lowercase() ?: ""
                loadHistoryList()
            }

            override fun afterTextChanged(s: Editable?) {
            }
        })

        updateFilterUi()
        loadHistoryList()
    }

    override fun onResume() {
        super.onResume()
        loadHistoryList()
    }

    private fun loadHistoryList() {
        historyContainer.removeAllViews()

        val fullHistoryList = ScanHistoryManager.getHistory(this)

        val filteredList = fullHistoryList.filter { item ->
            val matchesRisk = when (selectedFilter) {
                "ALL" -> true
                "SAFE" -> item.riskLabel.equals("SAFE", ignoreCase = true)
                "SUSPICIOUS" -> item.riskLabel.equals("SUSPICIOUS", ignoreCase = true)
                "MALICIOUS" -> item.riskLabel.equals("MALICIOUS", ignoreCase = true)
                "UNKNOWN" -> item.riskLabel.equals("UNKNOWN", ignoreCase = true)
                else -> true
            }

            val matchesSearch = if (searchQuery.isBlank()) {
                true
            } else {
                item.url.lowercase().contains(searchQuery) ||
                        item.riskLabel.lowercase().contains(searchQuery) ||
                        item.virusTotalStatus.lowercase().contains(searchQuery) ||
                        item.safeBrowsingStatus.lowercase().contains(searchQuery) ||
                        item.urlScanStatus.lowercase().contains(searchQuery) ||
                        item.redirectChain.lowercase().contains(searchQuery) ||
                        item.scannedAt.lowercase().contains(searchQuery)
            }

            matchesRisk && matchesSearch
        }

        if (filteredList.isEmpty()) {
            tvEmptyHistory.visibility = View.VISIBLE
            return
        }

        tvEmptyHistory.visibility = View.GONE

        for (item in filteredList) {
            val card = createHistoryCard(item)
            historyContainer.addView(card)
        }
    }

    private fun createHistoryCard(item: ScanHistoryItem): View {
        val card = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(18, 18, 18, 18)
            setBackgroundColor(Color.parseColor("#1B1F27"))

            val layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            )

            layoutParams.setMargins(0, 0, 0, 16)
            this.layoutParams = layoutParams

            isClickable = true
            isFocusable = true
        }

        val riskColor = when (item.riskLabel.uppercase()) {
            "SAFE" -> "#4CAF50"
            "SUSPICIOUS" -> "#FFC107"
            "MALICIOUS" -> "#F44336"
            else -> "#B0B7C3"
        }

        val tvRisk = TextView(this).apply {
            text = item.riskLabel
            setTextColor(Color.parseColor(riskColor))
            textSize = 20f
            setTypeface(null, Typeface.BOLD)
        }

        val tvScore = TextView(this).apply {
            text = "Score: ${item.riskScore}/100"
            setTextColor(Color.WHITE)
            textSize = 14f
            setPadding(0, 8, 0, 0)
        }

        val tvUrl = TextView(this).apply {
            text = item.url
            setTextColor(Color.WHITE)
            textSize = 15f
            setPadding(0, 10, 0, 0)
        }

        val tvDate = TextView(this).apply {
            text = "Scanned at: ${item.scannedAt}"
            setTextColor(Color.parseColor("#B0B7C3"))
            textSize = 13f
            setPadding(0, 8, 0, 0)
        }

        val tvApiSummary = TextView(this).apply {
            text = """
VirusTotal: ${item.virusTotalStatus}
Google Safe Browsing: ${item.safeBrowsingStatus}
urlscan.io: ${item.urlScanStatus}
            """.trimIndent()

            setTextColor(Color.parseColor("#B0B7C3"))
            textSize = 13f
            setPadding(0, 10, 0, 0)
        }

        val screenshotStatus = if (
            item.urlScanScreenshotUrl.isNotBlank() &&
            item.urlScanScreenshotUrl != "-"
        ) {
            "Screenshot: Saved"
        } else {
            "Screenshot: Not available"
        }

        val tvScreenshot = TextView(this).apply {
            text = screenshotStatus
            setTextColor(Color.parseColor("#B0B7C3"))
            textSize = 13f
            setPadding(0, 6, 0, 0)
        }

        val redirectStatus = if (
            item.redirectChain.isNotBlank() &&
            item.redirectChain != "Redirection information was not saved."
        ) {
            item.redirectChain.lineSequence()
                .firstOrNull { it.startsWith("Total redirects:") }
                ?: "Redirection chain: Saved"
        } else {
            "Redirection chain: Not available"
        }

        val tvRedirect = TextView(this).apply {
            text = redirectStatus
            setTextColor(Color.parseColor("#B0B7C3"))
            textSize = 13f
            setPadding(0, 6, 0, 0)
        }

        val tvHint = TextView(this).apply {
            text = "Tap to view • Hold to delete"
            setTextColor(Color.parseColor("#8A93A3"))
            textSize = 12f
            setPadding(0, 10, 0, 0)
        }

        card.addView(tvRisk)
        card.addView(tvScore)
        card.addView(tvUrl)
        card.addView(tvDate)
        card.addView(tvApiSummary)
        card.addView(tvRedirect)
        card.addView(tvScreenshot)
        card.addView(tvHint)

        card.setOnClickListener {
            openHistoryResult(item)
        }

        card.setOnLongClickListener {
            confirmDeleteItem(item)
            true
        }

        return card
    }

    private fun updateFilterUi() {
        val selectedBg = "#6C4AB6"
        val normalBg = "#1B1F27"

        filterAll.setBackgroundColor(Color.parseColor(if (selectedFilter == "ALL") selectedBg else normalBg))
        filterSafe.setBackgroundColor(Color.parseColor(if (selectedFilter == "SAFE") selectedBg else normalBg))
        filterSuspicious.setBackgroundColor(Color.parseColor(if (selectedFilter == "SUSPICIOUS") selectedBg else normalBg))
        filterMalicious.setBackgroundColor(Color.parseColor(if (selectedFilter == "MALICIOUS") selectedBg else normalBg))
        filterUnknown.setBackgroundColor(Color.parseColor(if (selectedFilter == "UNKNOWN") selectedBg else normalBg))
    }

    private fun openHistoryResult(item: ScanHistoryItem) {
        val intent = Intent(this, ResultActivity::class.java)

        intent.putExtra("SCANNED_URL", item.url)
        intent.putExtra("HISTORY_HIT", true)

        intent.putExtra("HISTORY_RISK_LABEL", item.riskLabel)
        intent.putExtra("HISTORY_RISK_SCORE", item.riskScore)
        intent.putExtra("HISTORY_SCANNED_AT", item.scannedAt)

        intent.putExtra("HISTORY_VALIDATION", item.validation)
        intent.putExtra("HISTORY_CHARACTERISTICS", item.characteristics)
        intent.putExtra("HISTORY_RISK_REASON", item.riskReason)
        intent.putExtra("HISTORY_REDIRECT_CHAIN", item.redirectChain)

        intent.putExtra("HISTORY_VT_STATUS", item.virusTotalStatus)
        intent.putExtra("HISTORY_VT_DETAILS", item.virusTotalDetails)

        intent.putExtra("HISTORY_SB_STATUS", item.safeBrowsingStatus)
        intent.putExtra("HISTORY_SB_DETAILS", item.safeBrowsingDetails)

        intent.putExtra("HISTORY_URLSCAN_STATUS", item.urlScanStatus)
        intent.putExtra("HISTORY_URLSCAN_DETAILS", item.urlScanDetails)
        intent.putExtra("HISTORY_URLSCAN_DOMAIN", item.urlScanDomain)
        intent.putExtra("HISTORY_URLSCAN_IP", item.urlScanIp)
        intent.putExtra("HISTORY_URLSCAN_COUNTRY", item.urlScanCountry)
        intent.putExtra("HISTORY_URLSCAN_UUID", item.urlScanUuid)

        // Important fix: pass screenshot URL to ResultActivity
        intent.putExtra("HISTORY_URLSCAN_SCREENSHOT_URL", item.urlScanScreenshotUrl)

        startActivity(intent)
    }

    private fun confirmClearHistory() {
        AlertDialog.Builder(this)
            .setTitle("Clear History")
            .setMessage("Are you sure you want to delete all scan history?")
            .setPositiveButton("Clear") { _, _ ->
                ScanHistoryManager.clearHistory(this)
                Toast.makeText(this, "History cleared", Toast.LENGTH_SHORT).show()
                loadHistoryList()
            }
            .setNegativeButton("Cancel", null)
            .show()
    }

    private fun confirmDeleteItem(item: ScanHistoryItem) {
        AlertDialog.Builder(this)
            .setTitle("Delete Scan")
            .setMessage("Delete this scan history item?\n\n${item.url}")
            .setPositiveButton("Delete") { _, _ ->
                ScanHistoryManager.deleteByUrl(this, item.url)
                Toast.makeText(this, "Scan deleted", Toast.LENGTH_SHORT).show()
                loadHistoryList()
            }
            .setNegativeButton("Cancel", null)
            .show()
    }
}
