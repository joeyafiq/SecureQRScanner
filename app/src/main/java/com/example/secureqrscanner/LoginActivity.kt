package com.example.secureqrscanner

import android.content.Intent
import android.os.Bundle
import android.widget.Button
import android.widget.EditText
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity

class LoginActivity : AppCompatActivity() {

    private lateinit var etLoginUsername: EditText
    private lateinit var etLoginPassword: EditText
    private lateinit var btnLogin: Button
    private lateinit var btnSetupAccount: Button

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // If no account has been created yet, go straight to Setup Account
        if (!SessionManager.isSetupDone(this)) {
            val intent = Intent(this, SetupAccountActivity::class.java)
            startActivity(intent)
            finish()
            return
        }

        // If user is already logged in, load API keys and go to MainActivity
        if (SessionManager.isLoggedIn(this)) {
            SessionManager.loadApiKeysToConfig(this)

            val intent = Intent(this, MainActivity::class.java)
            startActivity(intent)
            finish()
            return
        }

        setContentView(R.layout.activity_login)

        etLoginUsername = findViewById(R.id.etLoginUsername)
        etLoginPassword = findViewById(R.id.etLoginPassword)
        btnLogin = findViewById(R.id.btnLogin)
        btnSetupAccount = findViewById(R.id.btnSetupAccount)

        btnLogin.setOnClickListener {
            loginUser()
        }

        btnSetupAccount.setOnClickListener {
            val intent = Intent(this, SetupAccountActivity::class.java)
            startActivity(intent)
        }
    }

    private fun loginUser() {
        val username = etLoginUsername.text.toString().trim()
        val password = etLoginPassword.text.toString().trim()

        if (username.isBlank()) {
            etLoginUsername.error = "Username is required"
            etLoginUsername.requestFocus()
            return
        }

        if (password.isBlank()) {
            etLoginPassword.error = "Password is required"
            etLoginPassword.requestFocus()
            return
        }

        val loginSuccess = SessionManager.login(
            context = this,
            username = username,
            password = password
        )

        if (loginSuccess) {
            Toast.makeText(this, "Login successful", Toast.LENGTH_SHORT).show()

            val intent = Intent(this, MainActivity::class.java)
            startActivity(intent)
            finish()

        } else {
            Toast.makeText(this, "Invalid username or password", Toast.LENGTH_SHORT).show()
        }
    }
}