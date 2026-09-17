from app.detection.ransomware_engine import RansomwareDetectionEngine


engine = RansomwareDetectionEngine()


def test_ransomware_like_alert_is_detected():
    alert = {
        "threat": "Ransomware behavior detected",
    }

    result = engine.analyze(alert)

    assert result.detected is True
    assert result.detection_type == "ransomware_like"
    assert result.confidence >= 0.80


def test_mass_file_modification_is_detected():
    alert = {
        "activity": "Mass file modification",
        "modified_file_count": 500,
    }

    result = engine.analyze(alert)

    assert result.detected is True
    assert result.detection_type == "mass_file_modification"


def test_suspicious_encryption_is_detected():
    alert = {
        "activity": "Suspicious encryption activity detected",
    }

    result = engine.analyze(alert)

    assert result.detected is True
    assert result.detection_type == "suspicious_encryption"


def test_known_ransomware_from_edr_is_detected():
    alert = {
        "detection_name": "Known Ransomware Detection",
    }

    result = engine.analyze(alert)

    assert result.detected is True
    assert result.detection_type == "known_ransomware"
    assert result.confidence == 0.98


def test_high_confidence_malicious_process_is_detected():
    alert = {
        "process": "suspicious_process.exe",
        "verdict": "malicious",
        "confidence": 0.97,
    }

    result = engine.analyze(alert)

    assert result.detected is True
    assert result.detection_type == "malicious_process"
    assert result.confidence == 0.92


def test_benign_alert_is_not_detected():
    alert = {
        "process": "chrome.exe",
        "verdict": "clean",
        "confidence": 0.99,
        "activity": "Normal browser activity",
    }

    result = engine.analyze(alert)

    assert result.detected is False
    assert result.detection_type is None
    assert result.confidence == 0.0
    assert result.reasons == []


def test_multiple_ransomware_signals_are_combined():
    alert = {
        "detection_name": "Known Ransomware",
        "activity": "Mass encryption",
        "modified_file_count": 1000,
    }

    result = engine.analyze(alert)

    assert result.detected is True
    assert result.detection_type == "known_ransomware"
    assert len(result.reasons) >= 2