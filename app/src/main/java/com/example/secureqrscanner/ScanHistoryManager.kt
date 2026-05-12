package com.example.secureqrscanner

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject

object ScanHistoryManager {

    private const val PREF_NAME = "scan_history_storage"
    private const val KEY_HISTORY = "scan_history"
    private const val MAX_HISTORY = 50

    fun saveScan(
        context: Context,
        url: String,
        riskLabel: String,
        riskScore: Int,
        scannedAt: String,
        validation: String,
        characteristics: String,
        riskReason: String,
        redirectChain: String = "Redirection information was not saved.",
        virusTotalStatus: String,
        virusTotalDetails: String,
        safeBrowsingStatus: String,
        safeBrowsingDetails: String,
        urlScanStatus: String = "Not Available",
        urlScanDetails: String = "urlscan.io result was not saved.",
        urlScanDomain: String = "-",
        urlScanIp: String = "-",
        urlScanCountry: String = "-",
        urlScanUuid: String = "-",
        urlScanScreenshotUrl: String = "-"
    ) {
        val history = getHistory(context).toMutableList()

        val newItem = ScanHistoryItem(
            url = url,
            riskLabel = riskLabel,
            riskScore = riskScore,
            scannedAt = scannedAt,
            validation = validation,
            characteristics = characteristics,
            riskReason = riskReason,
            redirectChain = redirectChain,
            virusTotalStatus = virusTotalStatus,
            virusTotalDetails = virusTotalDetails,
            safeBrowsingStatus = safeBrowsingStatus,
            safeBrowsingDetails = safeBrowsingDetails,
            urlScanStatus = urlScanStatus,
            urlScanDetails = urlScanDetails,
            urlScanDomain = urlScanDomain,
            urlScanIp = urlScanIp,
            urlScanCountry = urlScanCountry,
            urlScanUuid = urlScanUuid,
            urlScanScreenshotUrl = urlScanScreenshotUrl
        )

        history.removeAll { it.url == url }
        history.add(0, newItem)

        val limitedHistory = history.take(MAX_HISTORY)
        val jsonArray = JSONArray()

        for (item in limitedHistory) {
            jsonArray.put(itemToJson(item))
        }

        context.getSharedPreferences(PREF_NAME, Context.MODE_PRIVATE)
            .edit()
            .putString(KEY_HISTORY, jsonArray.toString())
            .apply()
    }

    fun getHistory(context: Context): List<ScanHistoryItem> {
        val jsonString = context.getSharedPreferences(PREF_NAME, Context.MODE_PRIVATE)
            .getString(KEY_HISTORY, "[]") ?: "[]"

        val list = mutableListOf<ScanHistoryItem>()

        return try {
            val jsonArray = JSONArray(jsonString)

            for (i in 0 until jsonArray.length()) {
                val obj = jsonArray.getJSONObject(i)
                list.add(jsonToItem(obj))
            }

            list
        } catch (e: Exception) {
            emptyList()
        }
    }

    fun findByUrl(context: Context, url: String): ScanHistoryItem? {
        return getHistory(context).firstOrNull { it.url == url }
    }

    fun deleteByUrl(context: Context, url: String) {
        val history = getHistory(context).toMutableList()

        history.removeAll { it.url == url }

        val jsonArray = JSONArray()

        for (item in history) {
            jsonArray.put(itemToJson(item))
        }

        context.getSharedPreferences(PREF_NAME, Context.MODE_PRIVATE)
            .edit()
            .putString(KEY_HISTORY, jsonArray.toString())
            .apply()
    }

    fun clearHistory(context: Context) {
        context.getSharedPreferences(PREF_NAME, Context.MODE_PRIVATE)
            .edit()
            .remove(KEY_HISTORY)
            .apply()
    }

    private fun itemToJson(item: ScanHistoryItem): JSONObject {
        return JSONObject().apply {
            put("url", item.url)
            put("riskLabel", item.riskLabel)
            put("riskScore", item.riskScore)
            put("scannedAt", item.scannedAt)
            put("validation", item.validation)
            put("characteristics", item.characteristics)
            put("riskReason", item.riskReason)
            put("redirectChain", item.redirectChain)

            put("virusTotalStatus", item.virusTotalStatus)
            put("virusTotalDetails", item.virusTotalDetails)

            put("safeBrowsingStatus", item.safeBrowsingStatus)
            put("safeBrowsingDetails", item.safeBrowsingDetails)

            put("urlScanStatus", item.urlScanStatus)
            put("urlScanDetails", item.urlScanDetails)
            put("urlScanDomain", item.urlScanDomain)
            put("urlScanIp", item.urlScanIp)
            put("urlScanCountry", item.urlScanCountry)
            put("urlScanUuid", item.urlScanUuid)
            put("urlScanScreenshotUrl", item.urlScanScreenshotUrl)
        }
    }

    private fun jsonToItem(obj: JSONObject): ScanHistoryItem {
        return ScanHistoryItem(
            url = obj.optString("url", "-"),
            riskLabel = obj.optString("riskLabel", "UNKNOWN"),
            riskScore = obj.optInt("riskScore", 0),
            scannedAt = obj.optString("scannedAt", "-"),
            validation = obj.optString("validation", "-"),
            characteristics = obj.optString("characteristics", "-"),
            riskReason = obj.optString("riskReason", "-"),
            redirectChain = obj.optString(
                "redirectChain",
                "Redirection information was not saved."
            ),

            virusTotalStatus = obj.optString("virusTotalStatus", "Not Available"),
            virusTotalDetails = obj.optString("virusTotalDetails", "-"),

            safeBrowsingStatus = obj.optString("safeBrowsingStatus", "Not Available"),
            safeBrowsingDetails = obj.optString("safeBrowsingDetails", "-"),

            urlScanStatus = obj.optString("urlScanStatus", "Not Available"),
            urlScanDetails = obj.optString("urlScanDetails", "urlscan.io result was not saved."),
            urlScanDomain = obj.optString("urlScanDomain", "-"),
            urlScanIp = obj.optString("urlScanIp", "-"),
            urlScanCountry = obj.optString("urlScanCountry", "-"),
            urlScanUuid = obj.optString("urlScanUuid", "-"),
            urlScanScreenshotUrl = obj.optString("urlScanScreenshotUrl", "-")
        )
    }
}