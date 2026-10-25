# PRESENT Android app

This is a Kotlin Android wrapper for the PRESENT website.

- Website: https://present-1-u67u.onrender.com
- Application ID: `com.present.app`
- Android Studio project folder: `android/`

## Open in Android Studio

1. Download or clone this repository.
2. In Android Studio, choose **Open** and select the `android` folder.
3. Use JDK 17 and allow Gradle sync to finish.
4. Select an emulator or connected Android phone and press **Run**.

## Build a debug APK locally

From the `android` folder, run:

```bash
gradle assembleDebug
```

The APK is written to `app/build/outputs/apk/debug/app-debug.apk`.

## Daily logs and Excel

The app displays the existing website; it does not create a separate local activity database. Daily log persistence depends on the PRESENT website/backend and its configured database. If the website offers an Excel export/download, Android downloads are saved to the device's Downloads folder. To move the file to a laptop, transfer it by USB or cloud storage.

This wrapper alone does not add new daily-log or Excel-export features to the website.
