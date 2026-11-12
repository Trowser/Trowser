# Avoiding Windows SmartScreen Warnings

Trowser is signed with a self-signed certificate. Windows may show a "Windows protected your PC" or "Unknown publisher" warning when you first run it. You have two options:

## Option 1: Install the certificate (recommended)

Once installed, you will not see warnings when running Trowser.

1. **Double-click** `Trowser.cer` (in this folder).
2. Click **Install Certificate...**
3. Choose **Local Machine** (requires admin) or **Current User**.
4. Click **Next** → **Place all certificates in the following store**.
5. Click **Browse** → select **Trusted Root Certification Authorities**.
6. Click **Next** → **Finish**.
7. Confirm the security warning (you are trusting Trowser’s publisher).
8. Run `Trowser.exe` as usual.

## Option 2: Run without installing the certificate

You can run Trowser without installing the certificate:

1. When Windows blocks the app, click **More info**.
2. Click **Run anyway**.

You may need to do this the first time you run Trowser (or after updating it).

---

**Why is this needed?** Trowser uses a self-signed certificate because a commercial code-signing certificate is expensive. Installing `Trowser.cer` tells Windows to trust this specific certificate, so it will no longer show warnings for Trowser.
