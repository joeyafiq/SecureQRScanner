# Secure QR Scanner for Detecting Malicious and Suspicious URLs

An Android application that scans QR codes, extracts embedded URLs, evaluates suspicious URL characteristics, traces redirect chains, and verifies findings with external threat intelligence APIs.

## Core Features

- QR code scanning using CameraX and ML Kit barcode scanning
- URL validation and rule-based suspicious URL scoring
- Detection of lexical and structural indicators such as:
  - HTTP instead of HTTPS
  - Long URLs
  - IP-address URLs
  - URL shorteners
  - Suspicious TLDs
  - `@` symbol usage
  - Phishing-related keywords
  - Redirect-chain behaviour
- Redirect-chain tracing with OkHttp
- Threat intelligence integration with:
  - VirusTotal
  - Google Safe Browsing
  - urlscan.io
- Final verdict output with:
  - Risk label
  - Score band
  - Confidence level
  - Reason-for-risk explanation
  - API result summary
- Scan history storage and reload support
- PDF report generation and sharing

## Security-Oriented Design

- Passwords are stored as PBKDF2 hashes with salts
- API keys are encrypted with AES-GCM and protected through Android Keystore
- Backup exposure is disabled
- HTTPS-only network security configuration is used
- Legacy plaintext preference fields are cleaned automatically
- PDF sharing uses secure `FileProvider` URI permissions

## Project Structure

- `app/src/main/java/com/example/secureqrscanner/`
  - Main Android activities and feature logic
  - Rule-based URL analysis
  - Redirect tracing
  - Threat intelligence API clients
  - Session and history management
- `app/src/main/res/`
  - Layouts, drawables, and XML security configuration

## Requirements

- Android Studio
- Android SDK matching the project Gradle configuration
- Minimum Android version: API 29
- API keys for:
  - VirusTotal
  - Google Safe Browsing
  - urlscan.io

## Running the App

1. Open the project in Android Studio.
2. Sync Gradle.
3. Run the app on an emulator or Android device.
4. On first launch, create an account and enter the required API keys.
5. Scan a QR code and review the generated verdict, evidence, and history.

## Build Commands

```bash
./gradlew assembleDebug
./gradlew assembleRelease
```

Release signing material is intentionally excluded from version control.

## Testing Completed

- Functional testing of setup, login, scanning, verdict display, history, and PDF generation
- Integration testing of rule-based analysis with VirusTotal, Google Safe Browsing, and urlscan.io
- Security review using MobSF and Logcat-driven hardening

## Notes

- API keys are entered by the user at runtime and are not committed to the repository.
- A malicious verdict should come from trusted API confirmation; rule-based analysis is used to identify suspicious patterns and explain risk indicators.
