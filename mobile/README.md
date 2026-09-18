# AgentTrust Mobile

One Flutter app for Android and iOS. It connects directly to the AgentTrust FastAPI backend and stores only the JWT access token in Android encrypted storage or the iOS Keychain. Passwords are never stored.

## Run on Android emulator

Start PostgreSQL and the backend first. Then run:

```powershell
cd mobile
flutter pub get
flutter run --dart-define=API_BASE_URL=http://10.0.2.2:8000
```

`10.0.2.2` is the Android emulator address for the host computer. For a physical phone, use the computer's reachable local network address.

## Run on iOS simulator

On macOS with Xcode installed:

```bash
cd mobile
flutter pub get
cd ios && pod install && cd ..
flutter run --dart-define=API_BASE_URL=http://127.0.0.1:8000
```

Production builds must set an HTTPS URL:

```bash
flutter build apk --dart-define=API_BASE_URL=https://api.example.com
flutter build ios --dart-define=API_BASE_URL=https://api.example.com
```

## Checks

```powershell
flutter analyze
flutter test
flutter build apk --debug --dart-define=API_BASE_URL=http://10.0.2.2:8000
```
