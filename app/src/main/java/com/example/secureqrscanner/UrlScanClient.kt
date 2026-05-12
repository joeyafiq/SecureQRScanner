package com.example.secureqrscanner

import okhttp3.Call
import okhttp3.Callback
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.Response
import org.json.JSONObject
import java.io.IOException
import java.util.concurrent.TimeUnit

object UrlScanClient {

    private const val SUBMIT_URL = "https://urlscan.io/api/v1/scan/"

    data class UrlScanResult(
        val status: String,
        val verdict: String,
        val score: Int,
        val resultUrl: String,
        val screenshotUrl: String,
        val details: String,
        val finalUrl: String,
        val domain: String,
        val ip: String,
        val country: String,
        val uuid: String
    )

    private val client = OkHttpClient.Builder()
        .connectTimeout(20, TimeUnit.SECONDS)
        .readTimeout(30, TimeUnit.SECONDS)
        .writeTimeout(20, TimeUnit.SECONDS)
        .build()

    fun scanUrl(url: String, callback: (UrlScanResult?) -> Unit) {
        submitUrl(url) { apiResultUrl, publicResultUrl ->
            if (apiResultUrl == null) {
                callback(
                    UrlScanResult(
                        status = "Failed",
                        verdict = "Not Available",
                        score = 0,
                        resultUrl = "-",
                        screenshotUrl = "-",
                        details = "• Status: urlscan.io submission failed",
                        finalUrl = "-",
                        domain = "-",
                        ip = "-",
                        country = "-",
                        uuid = "-"
                    )
                )
                return@submitUrl
            }

            pollResult(
                apiResultUrl = apiResultUrl,
                publicResultUrl = publicResultUrl ?: "-",
                attempt = 1,
                callback = callback
            )
        }
    }

    private fun submitUrl(
        url: String,
        callback: (apiResultUrl: String?, publicResultUrl: String?) -> Unit
    ) {
        val requestJson = JSONObject().apply {
            put("url", url)
            put("visibility", "unlisted")
        }

        val mediaType = "application/json; charset=utf-8".toMediaType()
        val requestBody = requestJson.toString().toRequestBody(mediaType)

        val request = Request.Builder()
            .url(SUBMIT_URL)
            .addHeader("API-Key", ApiConfig.URLSCAN_API_KEY)
            .addHeader("Content-Type", "application/json")
            .post(requestBody)
            .build()

        client.newCall(request).enqueue(object : Callback {
            override fun onFailure(call: Call, e: IOException) {
                callback(null, null)
            }

            override fun onResponse(call: Call, response: Response) {
                response.use {
                    val body = it.body?.string()

                    if (!it.isSuccessful || body.isNullOrBlank()) {
                        callback(null, null)
                        return
                    }

                    try {
                        val jsonResponse = JSONObject(body)

                        val apiUrl = jsonResponse.optString("api", "")
                        val resultUrl = jsonResponse.optString("result", "")

                        if (apiUrl.isBlank()) {
                            callback(null, null)
                        } else {
                            callback(apiUrl, resultUrl)
                        }

                    } catch (e: Exception) {
                        callback(null, null)
                    }
                }
            }
        })
    }

    private fun pollResult(
        apiResultUrl: String,
        publicResultUrl: String,
        attempt: Int,
        callback: (UrlScanResult?) -> Unit
    ) {
        if (attempt > 6) {
            callback(
                UrlScanResult(
                    status = "Pending",
                    verdict = "Not Available",
                    score = 0,
                    resultUrl = publicResultUrl,
                    screenshotUrl = "-",
                    details = """
• Status: Scan submitted, but result is not ready yet
• Result: $publicResultUrl
• Screenshot: Not available yet
                    """.trimIndent(),
                    finalUrl = "-",
                    domain = "-",
                    ip = "-",
                    country = "-",
                    uuid = "-"
                )
            )
            return
        }

        val request = Request.Builder()
            .url(apiResultUrl)
            .addHeader("API-Key", ApiConfig.URLSCAN_API_KEY)
            .get()
            .build()

        Thread {
            try {
                Thread.sleep(5000)

                client.newCall(request).enqueue(object : Callback {
                    override fun onFailure(call: Call, e: IOException) {
                        callback(
                            UrlScanResult(
                                status = "Failed",
                                verdict = "Not Available",
                                score = 0,
                                resultUrl = publicResultUrl,
                                screenshotUrl = "-",
                                details = "• Status: urlscan.io result request failed",
                                finalUrl = "-",
                                domain = "-",
                                ip = "-",
                                country = "-",
                                uuid = "-"
                            )
                        )
                    }

                    override fun onResponse(call: Call, response: Response) {
                        response.use {
                            val body = it.body?.string()

                            if (it.code == 404 || it.code == 400) {
                                pollResult(
                                    apiResultUrl = apiResultUrl,
                                    publicResultUrl = publicResultUrl,
                                    attempt = attempt + 1,
                                    callback = callback
                                )
                                return
                            }

                            if (!it.isSuccessful || body.isNullOrBlank()) {
                                callback(
                                    UrlScanResult(
                                        status = "Failed",
                                        verdict = "Not Available",
                                        score = 0,
                                        resultUrl = publicResultUrl,
                                        screenshotUrl = "-",
                                        details = "• Status: urlscan.io result could not be retrieved",
                                        finalUrl = "-",
                                        domain = "-",
                                        ip = "-",
                                        country = "-",
                                        uuid = "-"
                                    )
                                )
                                return
                            }

                            try {
                                val resultJson = JSONObject(body)

                                val verdict = parseVerdict(resultJson)
                                val score = parseScore(verdict)

                                val task = resultJson.optJSONObject("task")
                                val page = resultJson.optJSONObject("page")

                                val finalUrl = page?.optString("url", "-") ?: "-"
                                val domain = page?.optString("domain", "-") ?: "-"
                                val ip = page?.optString("ip", "-") ?: "-"
                                val country = page?.optString("country", "-") ?: "-"
                                val uuid = task?.optString("uuid", "-") ?: "-"

                                val screenshotUrl = if (uuid != "-") {
                                    "https://urlscan.io/screenshots/$uuid.png"
                                } else {
                                    "-"
                                }

                                val details = """
• Status: $verdict
• Result: $publicResultUrl
• Screenshot: $screenshotUrl
                                """.trimIndent()

                                callback(
                                    UrlScanResult(
                                        status = "Completed",
                                        verdict = verdict,
                                        score = score,
                                        resultUrl = publicResultUrl,
                                        screenshotUrl = screenshotUrl,
                                        details = details,
                                        finalUrl = finalUrl,
                                        domain = domain,
                                        ip = ip,
                                        country = country,
                                        uuid = uuid
                                    )
                                )

                            } catch (e: Exception) {
                                callback(
                                    UrlScanResult(
                                        status = "Failed",
                                        verdict = "Not Available",
                                        score = 0,
                                        resultUrl = publicResultUrl,
                                        screenshotUrl = "-",
                                        details = "• Status: urlscan.io result parsing failed",
                                        finalUrl = "-",
                                        domain = "-",
                                        ip = "-",
                                        country = "-",
                                        uuid = "-"
                                    )
                                )
                            }
                        }
                    }
                })

            } catch (e: Exception) {
                callback(
                    UrlScanResult(
                        status = "Failed",
                        verdict = "Not Available",
                        score = 0,
                        resultUrl = publicResultUrl,
                        screenshotUrl = "-",
                        details = "• Status: urlscan.io scan polling failed",
                        finalUrl = "-",
                        domain = "-",
                        ip = "-",
                        country = "-",
                        uuid = "-"
                    )
                )
            }
        }.start()
    }

    private fun parseVerdict(resultJson: JSONObject): String {
        val verdicts = resultJson.optJSONObject("verdicts")
        val overall = verdicts?.optJSONObject("overall")

        val malicious = overall?.optBoolean("malicious", false) ?: false
        val score = overall?.optInt("score", 0) ?: 0

        return when {
            malicious -> "Malicious"
            score >= 50 -> "Suspicious"
            else -> "Clean"
        }
    }

    private fun parseScore(verdict: String): Int {
        return when (verdict) {
            "Malicious" -> 100
            "Suspicious" -> 30
            "Clean" -> 0
            else -> 0
        }
    }
}