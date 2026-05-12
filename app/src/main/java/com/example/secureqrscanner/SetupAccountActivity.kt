package com.example.secureqrscanner

import android.content.Intent
import android.os.Bundle
import android.widget.Button
import android.widget.EditText
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity

class SetupAccountActivity : AppCompatActivity() {

    private lateinit var etSetupUsername: EditText
    private lateinit var etSetupPassword: EditText
    private lateinit var etSetupConfirmPassword: EditText

    private lateinit var etVirusTotalApiKey: EditText
    private lateinit var etSafeBrowsingApiKey: EditText
    private lateinit var etUrlScanApiKey: EditText

    private lateinit var btnSaveAccount: Button
    private lateinit var btnGoToLogin: Button

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_setup_account)

        etSetupUsername = findViewById(R.id.etSetupUsername)
        etSetupPassword = findViewById(R.id.etSetupPassword)
        etSetupConfirmPassword = findViewById(R.id.etSetupConfirmPassword)

        etVirusTotalApiKey = findViewById(R.id.etVirusTotalApiKey)
        etSafeBrowsingApiKey = findViewById(R.id.etSafeBrowsingApiKey)
        etUrlScanApiKey = findViewById(R.id.etUrlScanApiKey)

        btnSaveAccount = findViewById(R.id.btnSaveAccount)
        btnGoToLogin = findViewById(R.id.btnGoToLogin)

        btnSaveAccount.setOnClickListener {
            saveAccount()
        }

        btnGoToLogin.setOnClickListener {
            goToLogin()
        }
    }

    private fun saveAccount() {
        val username = etSetupUsername.text.toString().trim()
        val password = etSetupPassword.text.toString().trim()
        val confirmPassword = etSetupConfirmPassword.text.toString().trim()

        val virusTotalApiKey = etVirusTotalApiKey.text.toString().trim()
        val safeBrowsingApiKey = etSafeBrowsingApiKey.text.toString().trim()
        val urlScanApiKey = etUrlScanApiKey.text.toString().trim()

        if (username.isBlank()) {
            etSetupUsername.error = "Username is required"
            etSetupUsername.requestFocus()
            return
        }

        if (password.isBlank()) {
            etSetupPassword.error = "Password is required"
            etSetupPassword.requestFocus()
            return
        }

        if (password.length < 4) {
            etSetupPassword.error = "Password must be at least 4 characters"
            etSetupPassword.requestFocus()
            return
        }

        if (confirmPassword.isBlank()) {
            etSetupConfirmPassword.error = "Confirm your password"
            etSetupConfirmPassword.requestFocus()
            return
        }

        if (password != confirmPassword) {
            etSetupConfirmPassword.error = "Passwords do not match"
            etSetupConfirmPassword.requestFocus()
            return
        }

        if (virusTotalApiKey.isBlank()) {
            etVirusTotalApiKey.error = "VirusTotal API key is required"
            etVirusTotalApiKey.requestFocus()
            return
        }

        if (safeBrowsingApiKey.isBlank()) {
            etSafeBrowsingApiKey.error = "Google Safe Browsing API key is required"
            etSafeBrowsingApiKey.requestFocus()
            return
        }

        if (urlScanApiKey.isBlank()) {
            etUrlScanApiKey.error = "urlscan.io API key is required"
            etUrlScanApiKey.requestFocus()
            return
        }

        SessionManager.saveAccount(
            context = this,
            username = username,
            password = password,
            virusTotalApiKey = virusTotalApiKey,
            safeBrowsingApiKey = safeBrowsingApiKey,
            urlScanApiKey = urlScanApiKey
        )

        Toast.makeText(
            this,
            "Account setup saved successfully",
            Toast.LENGTH_SHORT
        ).show()

        goToLogin()
    }

    private fun goToLogin() {
        val intent = Intent(this, LoginActivity::class.java)
        startActivity(intent)
        finish()
    }
}