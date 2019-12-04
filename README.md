[![CircleCI](https://circleci.com/gh/privacyidea/privacyidea-authenticator.svg?style=svg)](https://circleci.com/gh/privacyidea/privacyidea-authenticator)

# privacyIDEA Authenticator

The privacyIDEA Authenticator currently implements the HOTP and TOTP (30 and 60 seconds) algorithms with SHA-1/SHA-256/SHA-512.
It can scan QR codes according to the
[Google Authenticator Key URI](https://github.com/google/google-authenticator/wiki/Key-Uri-Format).

The privacyIDEA Authenticator also provides a more secure way of enrollment as
specified in our
[smartphone concept](https://github.com/privacyidea/privacyidea/wiki/concept%3A-SmartphoneApp) as well as the [pushtoken](https://github.com/privacyidea/privacyidea/wiki/concept%3A-PushToken) with support for user-configured firebase projects.

The App is best used with the
[privacyIDEA Authentication Server](https://github/privacyidea/privacyidea).

The iOS App can be found [here](https://github.com/privacyidea/privacyidea-authenticator-ios).

# Development

We are using Android Studio for development.

# Tests

Tests are located in ``app/src/androidTests``.

You can run the tests from within Android Studio. Please assure to have a necessary emulator installed.

# Todos

See the issues.

Ideas and pull requests are welcome.
