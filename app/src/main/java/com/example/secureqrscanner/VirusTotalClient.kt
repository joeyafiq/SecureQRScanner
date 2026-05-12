package com.example.secureqrscanner

import okhttp3.FormBody
import okhttp3.OkHttpClient
import okhttp3.Request
import org.json.JSONObject
import java.io.IOException
import java.util.concurrent.TimeUnit

object VirusTotalClient {

    private val client = OkHttpClient.Builder()
        .connectTimeout(10, TimeUnit.SECONDS)
        .readTimeout(15, TimeUnit.SECONDS)
        .writeTimeout(10, TimeUnit.SECONDS)
        .callTimeout(20, TimeUnit.SECONDS)
        .build()

    data class VirusTotalStats(
        val malicious: Int,
        val suspicious: Int,
        val harmless: Int,
        val undetected: Int
    )

    fun checkUrl(url: String, callback: (VirusTotalStats?) -> Unit) {
        submitUrl(url) { analysisId ->
            if (analysisId == null) {
                callback(null)
            } else {
                getAnalysisResultWithRetry(
                    analysisId = analysisId,
                    attempt = 1,
                    maxAttempts = 5,
                    callback = callback
                )
            }
        }
    }

    private fun submitUrl(url: String, callback: (String?) -> Unit) {
        val requestBody = FormBody.Builder()
            .add("url", url)
            .build()

        val request = Request.Builder()
            .url("https://www.virustotal.com/api/v3/urls")
            .addHeader("x-apikey", ApiConfig.VIRUSTOTAL_API_KEY)
            .post(requestBody)
            .build()

        client.newCall(request).enqueue(object : okhttp3.Callback {
            override fun onFailure(call: okhttp3.Call, e: IOException) {
                callback(null)
            }

            override fun onResponse(call: okhttp3.Call, response: okhttp3.Response) {
                val body = response.body?.string()

                if (!response.isSuccessful || body == null) {
                    callback(null)
                    return
                }

                try {
                    val json = JSONObject(body)
                    val analysisId = json
                        .getJSONObject("data")
                        .getString("id")

                    callback(analysisId)
                } catch (e: Exception) {
                    callback(null)
                }
            }
        })
    }

    private fun getAnalysisResultWithRetry(
        analysisId: String,
        attempt: Int,
        maxAttempts: Int,
        callback: (VirusTotalStats?) -> Unit
    ) {
        val request = Request.Builder()
            .url("https://www.virustotal.com/api/v3/analyses/$analysisId")
            .addHeader("x-apikey", ApiConfig.VIRUSTOTAL_API_KEY)
            .get()
            .build()

        client.newCall(request).enqueue(object : okhttp3.Callback {
            override fun onFailure(call: okhttp3.Call, e: IOException) {
                callback(null)
            }

            override fun onResponse(call: okhttp3.Call, response: okhttp3.Response) {
                val body = response.body?.string()

                if (!response.isSuccessful || body == null) {
                    callback(null)
                    return
                }

                try {
                    val json = JSONObject(body)
                    val attributes = json
                        .getJSONObject("data")
                        .getJSONObject("attributes")

                    val status = attributes.optString("status", "unknown")

                    if (status != "completed") {
                        if (attempt < maxAttempts) {
                            Thread.sleep(3000)

                            getAnalysisResultWithRetry(
                                analysisId = analysisId,
                                attempt = attempt + 1,
                                maxAttempts = maxAttempts,
                                callback = callback
                            )
                        } else {
                            callback(null)
                        }
                        return
                    }

                    val stats = attributes.getJSONObject("stats")

                    val result = VirusTotalStats(
                        malicious = stats.optInt("malicious", 0),
                        suspicious = stats.optInt("suspicious", 0),
                        harmless = stats.optInt("harmless", 0),
                        undetected = stats.optInt("undetected", 0)
                    )

                    callback(result)

                } catch (e: Exception) {
                    callback(null)
                }
            }
        })
    }
}
