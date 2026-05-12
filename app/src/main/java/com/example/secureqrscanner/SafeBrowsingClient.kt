package com.example.secureqrscanner

import okhttp3.Call
import okhttp3.Callback
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.Response
import org.json.JSONArray
import org.json.JSONObject
import java.io.IOException
import java.util.concurrent.TimeUnit

object SafeBrowsingClient {

    data class SafeBrowsingResult(
        val hasThreat: Boolean,
        val threatTypes: List<String>
    )

    private val client = OkHttpClient.Builder()
        .connectTimeout(20, TimeUnit.SECONDS)
        .readTimeout(30, TimeUnit.SECONDS)
        .writeTimeout(20, TimeUnit.SECONDS)
        .build()

    fun checkUrl(url: String, callback: (SafeBrowsingResult?) -> Unit) {

        if (ApiConfig.GOOGLE_SAFE_BROWSING_API_KEY.isBlank()) {
            callback(null)
            return
        }

        val jsonBody = JSONObject().apply {
            put("client", JSONObject().apply {
                put("clientId", "secureqrscanner")
                put("clientVersion", "1.0")
            })

            put("threatInfo", JSONObject().apply {
                put("threatTypes", JSONArray().apply {
                    put("MALWARE")
                    put("SOCIAL_ENGINEERING")
                    put("UNWANTED_SOFTWARE")
                    put("POTENTIALLY_HARMFUL_APPLICATION")
                })

                put("platformTypes", JSONArray().apply {
                    put("ANY_PLATFORM")
                })

                put("threatEntryTypes", JSONArray().apply {
                    put("URL")
                })

                put("threatEntries", JSONArray().apply {
                    put(JSONObject().apply {
                        put("url", url)
                    })
                })
            })
        }

        val mediaType = "application/json; charset=utf-8".toMediaType()
        val requestBody = jsonBody.toString().toRequestBody(mediaType)

        val request = Request.Builder()
            .url("https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${ApiConfig.GOOGLE_SAFE_BROWSING_API_KEY}")
            .post(requestBody)
            .build()

        client.newCall(request).enqueue(object : Callback {

            override fun onFailure(call: Call, e: IOException) {
                callback(null)
            }

            override fun onResponse(call: Call, response: Response) {
                response.use {
                    val body = it.body?.string()

                    if (!it.isSuccessful || body.isNullOrBlank()) {
                        callback(null)
                        return
                    }

                    try {
                        val jsonResponse = JSONObject(body)

                        if (!jsonResponse.has("matches")) {
                            callback(
                                SafeBrowsingResult(
                                    hasThreat = false,
                                    threatTypes = emptyList()
                                )
                            )
                            return
                        }

                        val matches = jsonResponse.optJSONArray("matches")
                        val threatTypes = mutableListOf<String>()

                        if (matches != null) {
                            for (i in 0 until matches.length()) {
                                val match = matches.optJSONObject(i)
                                val threatType = match?.optString("threatType", "")

                                if (!threatType.isNullOrBlank()) {
                                    threatTypes.add(threatType)
                                }
                            }
                        }

                        callback(
                            SafeBrowsingResult(
                                hasThreat = threatTypes.isNotEmpty(),
                                threatTypes = threatTypes.distinct()
                            )
                        )

                    } catch (e: Exception) {
                        callback(null)
                    }
                }
            }
        })
    }
}