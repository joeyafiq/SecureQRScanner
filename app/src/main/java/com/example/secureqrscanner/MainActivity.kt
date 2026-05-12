package com.example.secureqrscanner

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Bundle
import android.widget.Button
import android.widget.TextView
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.annotation.OptIn
import androidx.appcompat.app.AppCompatActivity
import androidx.camera.core.CameraSelector
import androidx.camera.core.ExperimentalGetImage
import androidx.camera.core.ImageAnalysis
import androidx.camera.core.Preview
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.view.PreviewView
import androidx.core.content.ContextCompat
import com.google.mlkit.vision.barcode.BarcodeScannerOptions
import com.google.mlkit.vision.barcode.BarcodeScanning
import com.google.mlkit.vision.barcode.common.Barcode
import com.google.mlkit.vision.common.InputImage
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors

class MainActivity : AppCompatActivity() {

    private lateinit var previewView: PreviewView
    private lateinit var btnPickGallery: Button
    private lateinit var btnHistory: Button
    private lateinit var btnLogout: TextView

    private lateinit var cameraExecutor: ExecutorService

    private var hasScanned = false
    private var cameraProvider: ProcessCameraProvider? = null

    private val qrScanner by lazy {
        val options = BarcodeScannerOptions.Builder()
            .setBarcodeFormats(Barcode.FORMAT_QR_CODE)
            .build()

        BarcodeScanning.getClient(options)
    }

    private val requestCameraPermissionLauncher =
        registerForActivityResult(ActivityResultContracts.RequestPermission()) { isGranted ->
            if (isGranted) {
                startCamera()
            } else {
                Toast.makeText(
                    this,
                    "Camera permission denied. Use gallery scan instead.",
                    Toast.LENGTH_SHORT
                ).show()
            }
        }

    private val pickImageLauncher =
        registerForActivityResult(ActivityResultContracts.GetContent()) { uri: Uri? ->
            if (uri != null) {
                scanQrFromGallery(uri)
            } else {
                Toast.makeText(this, "No image selected", Toast.LENGTH_SHORT).show()
            }
        }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        SessionManager.loadApiKeysToConfig(this)

        setContentView(R.layout.activity_main)

        previewView = findViewById(R.id.previewView)
        btnPickGallery = findViewById(R.id.btnPickGallery)
        btnHistory = findViewById(R.id.btnHistory)
        btnLogout = findViewById(R.id.btnLogout)

        cameraExecutor = Executors.newSingleThreadExecutor()

        btnPickGallery.setOnClickListener {
            pickImageLauncher.launch("image/*")
        }

        btnHistory.setOnClickListener {
            val intent = Intent(this, HistoryActivity::class.java)
            startActivity(intent)
        }

        btnLogout.setOnClickListener {
            SessionManager.logout(this)

            val intent = Intent(this, LoginActivity::class.java)
            intent.flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK
            startActivity(intent)
            finish()
        }

    }

    override fun onResume() {
        super.onResume()
        hasScanned = false
        startCameraIfPermissionGranted()
    }

    override fun onPause() {
        cameraProvider?.unbindAll()
        super.onPause()
    }

    private fun startCameraIfPermissionGranted() {
        val permissionGranted = ContextCompat.checkSelfPermission(
            this,
            Manifest.permission.CAMERA
        ) == PackageManager.PERMISSION_GRANTED

        if (permissionGranted) {
            startCamera()
        } else {
            requestCameraPermissionLauncher.launch(Manifest.permission.CAMERA)
        }
    }

    @OptIn(ExperimentalGetImage::class)
    private fun startCamera() {
        val cameraProviderFuture = ProcessCameraProvider.getInstance(this)

        cameraProviderFuture.addListener({
            try {
                val cameraProvider = cameraProviderFuture.get()
                this.cameraProvider = cameraProvider

                val preview = Preview.Builder()
                    .build()
                    .also {
                        it.setSurfaceProvider(previewView.surfaceProvider)
                    }

                val imageAnalysis = ImageAnalysis.Builder()
                    .setBackpressureStrategy(ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST)
                    .build()

                imageAnalysis.setAnalyzer(cameraExecutor) { imageProxy ->
                    if (hasScanned) {
                        imageProxy.close()
                        return@setAnalyzer
                    }

                    val mediaImage = imageProxy.image

                    if (mediaImage != null) {
                        val image = InputImage.fromMediaImage(
                            mediaImage,
                            imageProxy.imageInfo.rotationDegrees
                        )

                        qrScanner.process(image)
                            .addOnSuccessListener { barcodes ->
                                for (barcode in barcodes) {
                                    val scannedValue = barcode.rawValue

                                    if (!scannedValue.isNullOrBlank() && !hasScanned) {
                                        hasScanned = true
                                        goToLoadingActivity(scannedValue)
                                        break
                                    }
                                }
                            }
                            .addOnFailureListener {
                                Toast.makeText(
                                    this,
                                    "QR scan failed. Try again.",
                                    Toast.LENGTH_SHORT
                                ).show()
                            }
                            .addOnCompleteListener {
                                imageProxy.close()
                            }
                    } else {
                        imageProxy.close()
                    }
                }

                val cameraSelector = CameraSelector.DEFAULT_BACK_CAMERA

                cameraProvider.unbindAll()

                cameraProvider.bindToLifecycle(
                    this,
                    cameraSelector,
                    preview,
                    imageAnalysis
                )

            } catch (e: Exception) {
                Toast.makeText(
                    this,
                    "Failed to start camera: ${e.message}",
                    Toast.LENGTH_SHORT
                ).show()
            }

        }, ContextCompat.getMainExecutor(this))
    }

    private fun scanQrFromGallery(uri: Uri) {
        try {
            val image = InputImage.fromFilePath(this, uri)

            qrScanner.process(image)
                .addOnSuccessListener { barcodes ->
                    if (barcodes.isEmpty()) {
                        Toast.makeText(
                            this,
                            "No QR code found in selected image",
                            Toast.LENGTH_SHORT
                        ).show()
                        return@addOnSuccessListener
                    }

                    val scannedValue = barcodes.firstOrNull()?.rawValue

                    if (scannedValue.isNullOrBlank()) {
                        Toast.makeText(
                            this,
                            "QR code content is empty",
                            Toast.LENGTH_SHORT
                        ).show()
                    } else {
                        goToLoadingActivity(scannedValue)
                    }
                }
                .addOnFailureListener {
                    Toast.makeText(
                        this,
                        "Failed to scan selected image",
                        Toast.LENGTH_SHORT
                    ).show()
                }

        } catch (e: Exception) {
            Toast.makeText(
                this,
                "Unable to read selected image: ${e.message}",
                Toast.LENGTH_SHORT
            ).show()
        }
    }

    private fun goToLoadingActivity(scannedContent: String) {
        cameraProvider?.unbindAll()

        val intent = Intent(this, LoadingActivity::class.java)
        intent.putExtra("SCANNED_URL", scannedContent)
        startActivity(intent)
    }

    override fun onDestroy() {
        super.onDestroy()

        cameraExecutor.shutdown()
        qrScanner.close()
    }
}
