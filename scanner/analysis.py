from __future__ import annotations

import hashlib
import os
import re
import shutil
import subprocess
import zipfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

MAX_APK_BYTES = 50 * 1024 * 1024
MAX_EXPANDED_BYTES = 200 * 1024 * 1024
MAX_ENTRIES = 12000
ANDROID = "{http://schemas.android.com/apk/res/android}"


class InvalidAPK(ValueError):
    pass


def validate_archive(path: Path) -> None:
    """Inspect ZIP metadata without extracting or executing any member."""
    if not 0 < path.stat().st_size <= MAX_APK_BYTES:
        raise InvalidAPK("APK must be nonempty and at most 50 MB.")
    try:
        with zipfile.ZipFile(path) as archive:
            entries = archive.infolist()
            if len(entries) > MAX_ENTRIES:
                raise InvalidAPK("Archive contains too many entries.")
            names = set()
            total = 0
            for entry in entries:
                name = entry.filename.replace("\\", "/")
                parts = PurePosixPath(name).parts
                if name.startswith("/") or ".." in parts or any(":" in p for p in parts):
                    raise InvalidAPK("Archive contains unsafe paths.")
                if name in names:
                    raise InvalidAPK("Archive contains duplicate entries.")
                names.add(name)
                if entry.flag_bits & 1:
                    raise InvalidAPK("Encrypted APK members are unsupported.")
                if entry.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
                    raise InvalidAPK("Unsupported APK compression method.")
                total += entry.file_size
                if total > MAX_EXPANDED_BYTES or entry.file_size > MAX_EXPANDED_BYTES:
                    raise InvalidAPK("Archive expanded size exceeds the inspection limit.")
                if entry.file_size > 1024 * 1024 and entry.file_size / max(entry.compress_size, 1) > 1000:
                    raise InvalidAPK("Archive compression ratio exceeds the inspection limit.")
            if "AndroidManifest.xml" not in names:
                raise InvalidAPK("An APK must contain AndroidManifest.xml.")
            manifest = archive.getinfo("AndroidManifest.xml")
            if manifest.file_size > 2 * 1024 * 1024:
                raise InvalidAPK("Manifest exceeds the inspection limit.")
    except (zipfile.BadZipFile, EOFError, RuntimeError) as exc:
        raise InvalidAPK("File is not a readable APK archive.") from exc


def apksigner_command() -> list[str] | None:
    jar = os.getenv("APKSIGNER_JAR")
    java = os.getenv("JAVA_BIN") or shutil.which("java")
    root = Path(__file__).resolve().parent.parent
    if jar and not Path(jar).is_absolute():
        jar = str(root / jar)
    if os.getenv("JAVA_BIN") and java and not Path(java).is_absolute():
        java = str(root / java)
    if jar and Path(jar).is_file() and java:
        return [java, "-Xmx192m", "-jar", jar]
    binary = os.getenv("APKSIGNER_BIN") or shutil.which("apksigner")
    if binary:
        return [binary]
    return None


def verify_signature(path: Path) -> dict:
    command = apksigner_command()
    if command is None:
        return {"status": "unavailable", "signer_sha256": [], "schemes": [], "errors": ["Android apksigner is not installed on this scanner."]}
    try:
        proc = subprocess.run(command + ["verify", "--verbose", "--print-certs", str(path)], capture_output=True, text=True, timeout=20, encoding="utf-8", errors="replace")
    except (OSError, subprocess.TimeoutExpired):
        return {"status": "unavailable", "signer_sha256": [], "schemes": [], "errors": ["Signature verification could not complete within its resource limit."]}
    output = proc.stdout + "\n" + proc.stderr
    if proc.returncode != 0:
        # Never publish certificate subjects, filesystem paths, or arbitrary verifier text.
        failed_verification = "DOES NOT VERIFY" in output or "Failed to verify APK" in output
        return {"status": "invalid" if failed_verification else "unavailable", "signer_sha256": [], "schemes": [], "errors": ["Android apksigner did not verify this APK for its declared SDK range." if failed_verification else "The signature verifier encountered an infrastructure or compatibility error."]}
    certs = sorted(set(x.lower() for x in re.findall(r"Signer #\d+ certificate SHA-256 digest:\s*([a-fA-F0-9]{64})", output)))
    schemes = [m.group(1) for m in re.finditer(r"Verified using (v[\d.]+) scheme[^\n]*:\s*true", output)]
    if not certs:
        return {"status": "unavailable", "signer_sha256": [], "schemes": schemes, "errors": ["Verifier completed but signer fingerprints could not be extracted."]}
    return {"status": "verified", "signer_sha256": certs, "schemes": schemes, "errors": []}


# The descriptions concern requested capabilities, never observed behavior.
SENSITIVE = {
    "READ_SMS": ("Requests access to read SMS messages.", "एसएमएस संदेश पढ़ने की अनुमति माँगता है।"),
    "RECEIVE_SMS": ("Requests access to receive SMS messages.", "एसएमएस संदेश प्राप्त करने की अनुमति माँगता है।"),
    "SEND_SMS": ("Requests permission to send SMS messages.", "एसएमएस संदेश भेजने की अनुमति माँगता है।"),
    "READ_CONTACTS": ("Requests access to contacts.", "संपर्कों तक पहुँच की अनुमति माँगता है।"),
    "WRITE_CONTACTS": ("Requests permission to change contacts.", "संपर्क बदलने की अनुमति माँगता है।"),
    "READ_CALL_LOG": ("Requests access to call history.", "कॉल इतिहास तक पहुँच की अनुमति माँगता है।"),
    "WRITE_CALL_LOG": ("Requests permission to change call history.", "कॉल इतिहास बदलने की अनुमति माँगता है।"),
    "RECORD_AUDIO": ("Requests microphone access.", "माइक्रोफ़ोन तक पहुँच की अनुमति माँगता है।"),
    "CAMERA": ("Requests camera access.", "कैमरे तक पहुँच की अनुमति माँगता है।"),
    "ACCESS_FINE_LOCATION": ("Requests precise location access.", "सटीक स्थान तक पहुँच की अनुमति माँगता है।"),
    "ACCESS_COARSE_LOCATION": ("Requests approximate location access.", "अनुमानित स्थान तक पहुँच की अनुमति माँगता है।"),
    "ACCESS_BACKGROUND_LOCATION": ("Requests location access in the background.", "पृष्ठभूमि में स्थान तक पहुँच की अनुमति माँगता है।"),
    "READ_PHONE_STATE": ("Requests access to phone state and related device information.", "फ़ोन की स्थिति और संबंधित जानकारी तक पहुँच की अनुमति माँगता है।"),
    "READ_PHONE_NUMBERS": ("Requests access to phone numbers available to the device.", "डिवाइस पर उपलब्ध फ़ोन नंबरों तक पहुँच की अनुमति माँगता है।"),
    "CALL_PHONE": ("Requests permission to initiate phone calls.", "फ़ोन कॉल शुरू करने की अनुमति माँगता है।"),
    "ANSWER_PHONE_CALLS": ("Requests permission to answer phone calls.", "फ़ोन कॉल का उत्तर देने की अनुमति माँगता है।"),
    "READ_MEDIA_IMAGES": ("Requests access to images in shared media storage.", "साझा मीडिया स्टोरेज की छवियों तक पहुँच माँगता है।"),
    "READ_MEDIA_VIDEO": ("Requests access to video in shared media storage.", "साझा मीडिया स्टोरेज के वीडियो तक पहुँच माँगता है।"),
    "READ_MEDIA_AUDIO": ("Requests access to audio in shared media storage.", "साझा मीडिया स्टोरेज के ऑडियो तक पहुँच माँगता है।"),
    "READ_MEDIA_VISUAL_USER_SELECTED": ("Requests access to user-selected photos and videos.", "उपयोगकर्ता द्वारा चुनी गई फ़ोटो और वीडियो तक पहुँच माँगता है।"),
    "BLUETOOTH_SCAN": ("Requests permission to discover nearby Bluetooth devices.", "आस-पास के ब्लूटूथ डिवाइस खोजने की अनुमति माँगता है।"),
    "BLUETOOTH_CONNECT": ("Requests access to connect with Bluetooth devices.", "ब्लूटूथ डिवाइस से जुड़ने की अनुमति माँगता है।"),
    "BODY_SENSORS": ("Requests access to supported body sensor readings.", "शरीर संबंधी सेंसर रीडिंग तक पहुँच माँगता है।"),
    "BODY_SENSORS_BACKGROUND": ("Requests body sensor access in the background.", "पृष्ठभूमि में शरीर संबंधी सेंसर तक पहुँच माँगता है।"),
    "SYSTEM_ALERT_WINDOW": ("Requests permission to draw over other applications.", "अन्य ऐप्स के ऊपर दिखाने की अनुमति माँगता है।"),
    "REQUEST_INSTALL_PACKAGES": ("Requests the ability to ask Android to install other packages.", "अन्य ऐप पैकेज स्थापित करने का अनुरोध करने की अनुमति माँगता है।"),
    "MANAGE_EXTERNAL_STORAGE": ("Requests broad shared-storage access.", "साझा स्टोरेज तक व्यापक पहुँच की अनुमति माँगता है।"),
    "READ_EXTERNAL_STORAGE": ("Requests access to shared files; actual scope depends on Android version.", "साझा फ़ाइलों तक पहुँच माँगता है; वास्तविक दायरा एंड्रॉयड संस्करण पर निर्भर है।"),
    "WRITE_EXTERNAL_STORAGE": ("Requests shared-storage writes; actual scope depends on Android version.", "साझा स्टोरेज में लिखने की अनुमति माँगता है; दायरा एंड्रॉयड संस्करण पर निर्भर है।"),
    "QUERY_ALL_PACKAGES": ("Requests broad visibility of installed package names.", "स्थापित ऐप्स के नामों की व्यापक जानकारी की अनुमति माँगता है।"),
}


def permission_record(name: str) -> dict:
    short = name.rsplit(".", 1)[-1]
    descriptions = SENSITIVE.get(short) if name.startswith("android.permission.") else None
    sensitive = descriptions is not None
    if descriptions is None:
        descriptions = ("Declared permission. Its effect depends on Android enforcement and runtime grants.", "घोषित अनुमति। इसका प्रभाव एंड्रॉयड और रनटाइम स्वीकृति पर निर्भर है।")
    return {"name": name, "category": "sensitive" if sensitive else "standard", "description_en": descriptions[0], "description_hi": descriptions[1]}


def finding(id: str, severity: str, title: str, title_hi: str, evidence: list[str], explanation: str, explanation_hi: str) -> dict:
    return {"id": id, "severity": severity, "title_en": title, "title_hi": title_hi, "evidence": evidence, "explanation_en": explanation, "explanation_hi": explanation_hi}


def analyze_apk(path: Path) -> dict:
    validate_archive(path)
    from loguru import logger
    logger.remove()
    from androguard.core.apk import APK

    try:
        apk = APK(str(path))
        if not apk.is_valid_APK():
            raise InvalidAPK("Android manifest could not be parsed.")
        xml = apk.get_android_manifest_xml()
        if xml is None:
            raise InvalidAPK("Android manifest is missing or unsupported.")
        package = apk.get_package()
        if not isinstance(package, str) or not package or len(package) > 255:
            raise InvalidAPK("APK package identity is invalid.")
        app = xml.find("application")
        raw_permissions = sorted(set(apk.get_permissions()))
        if len(raw_permissions) > 500:
            raise InvalidAPK("APK declares too many permissions.")
        permissions = [permission_record(p[:512]) for p in raw_permissions]
        version_raw = apk.get_androidversion_code()
        try:
            version = int(version_raw) if version_raw is not None else None
        except (TypeError, ValueError):
            version = None
        version_name = apk.get_androidversion_name()
        app_name = apk.get_app_name()
        target_raw = apk.get_target_sdk_version()
        try:
            target_sdk = int(target_raw) if target_raw else None
        except (TypeError, ValueError):
            target_sdk = None
    except InvalidAPK:
        raise
    except Exception as exc:
        raise InvalidAPK("APK metadata parser could not complete. Split APKs and malformed manifests may be unsupported.") from exc

    signature = verify_signature(path)
    findings = []
    sensitive = [p["name"] for p in permissions if p["category"] == "sensitive"]
    if sensitive:
        findings.append(finding("sensitive-permissions", "review", "Sensitive capabilities requested", "संवेदनशील क्षमताएँ माँगी गई हैं", sensitive, "Check whether these permissions are necessary for the app's purpose. A declaration is not evidence that access was granted or abused.", "जाँचें कि ये अनुमतियाँ ऐप के काम के लिए ज़रूरी हैं या नहीं। घोषणा से यह साबित नहीं होता कि पहुँच मिली या उसका दुरुपयोग हुआ।"))
    if signature["status"] == "invalid":
        findings.append(finding("signature-invalid", "high", "APK signature did not verify", "एपीके हस्ताक्षर सत्यापित नहीं हुआ", signature["errors"], "Avoid installing this file until the publisher provides a verifiable release. This finding does not identify malware.", "प्रकाशक से सत्यापित रिलीज़ मिलने तक इसे स्थापित करने से बचें। यह निष्कर्ष मैलवेयर की पहचान नहीं है।"))
    elif signature["status"] == "unavailable":
        findings.append(finding("signature-unavailable", "info", "Signature check incomplete", "हस्ताक्षर जाँच अधूरी है", signature["errors"], "Signing identity could not be verified. Do not interpret missing results as a safe result.", "हस्ताक्षर पहचान सत्यापित नहीं हो सकी। परिणाम न मिलने को सुरक्षित होने का प्रमाण न मानें।"))
    if app is not None and app.get(ANDROID + "debuggable", "false").lower() == "true":
        findings.append(finding("debuggable", "review", "Debugging is enabled", "डिबगिंग चालू है", ["android:debuggable=true"], "This build permits debugging. That can be expected for a training or development app, but deserves review in a production release.", "यह बिल्ड डिबगिंग की अनुमति देता है। प्रशिक्षण ऐप में यह अपेक्षित है, लेकिन प्रोडक्शन रिलीज़ में समीक्षा ज़रूरी है।"))
    if app is not None and app.get(ANDROID + "usesCleartextTraffic", "").lower() == "true":
        findings.append(finding("cleartext-opt-in", "review", "Cleartext networking is opted in", "असुरक्षित नेटवर्किंग की अनुमति घोषित है", ["android:usesCleartextTraffic=true"], "The manifest opts into cleartext traffic. Network security configuration and actual behavior have not been inspected.", "मैनिफ़ेस्ट में क्लियरटेक्स्ट ट्रैफ़िक की अनुमति है। नेटवर्क सुरक्षा कॉन्फ़िगरेशन और वास्तविक व्यवहार की जाँच नहीं हुई है।"))
    if target_sdk is not None and target_sdk < 28:
        findings.append(finding("legacy-target", "review", "Older Android protections targeted", "पुरानी एंड्रॉयड सुरक्षा लक्षित है", [f"targetSdkVersion={target_sdk}"], "An older target SDK can retain legacy platform behavior. This is a compatibility indicator, not proof of harmful activity.", "पुराने टारगेट एसडीके से पुराना प्लेटफ़ॉर्म व्यवहार रह सकता है। यह संगतता संकेत है, हानिकारक गतिविधि का प्रमाण नहीं।"))
    if app is not None:
        services = [s for s in app.findall("service") if s.get(ANDROID + "permission") == "android.permission.BIND_ACCESSIBILITY_SERVICE"]
        if services:
            findings.append(finding("accessibility-service", "review", "Accessibility service declared", "एक्सेसिबिलिटी सेवा घोषित है", ["service permission=android.permission.BIND_ACCESSIBILITY_SERVICE"], "If enabled by the user, an accessibility service may interact with screen content. Legitimate accessibility tools also use this capability.", "उपयोगकर्ता के चालू करने पर यह सेवा स्क्रीन सामग्री से संपर्क कर सकती है। वैध एक्सेसिबिलिटी ऐप्स भी इसका उपयोग करते हैं।"))
    with path.open("rb") as handle:
        digest = hashlib.file_digest(handle, "sha256").hexdigest() if hasattr(hashlib, "file_digest") else hashlib.sha256(handle.read()).hexdigest()
    return {
        "schema_version": 1, "apk_sha256": digest, "file_size": path.stat().st_size,
        "package_name": package, "version_name": str(version_name)[:128] if version_name is not None else None,
        "version_code": version, "app_name": str(app_name)[:128] if app_name else None,
        "signature": signature, "permissions": permissions, "findings": findings,
        "coverage": {"manifest": True, "signature": signature["status"] != "unavailable", "dex": False,
                     "notes": ["Static inspection only; the APK was not installed or executed.", "Declared permissions are capabilities, not observed grants or behavior.", "DEX behavior, remote code, network security resources, and signer rotation lineage are not assessed.", "No findings does not establish that an app is safe."]},
        "analyzed_at": datetime.now(timezone.utc).isoformat(),
    }
