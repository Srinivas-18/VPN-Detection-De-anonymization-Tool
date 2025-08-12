def guess_os_from_ttl(ttl):
    if ttl >= 128:
        return "Windows (TTL≈128)"
    elif ttl >= 64:
        return "Linux/macOS (TTL≈64)"
    elif ttl >= 32:
        return "Old Unix (TTL≈32)"
    else:
        return "Unknown OS"

def classify_fingerprint(fingerprint):
    ttl = fingerprint.get("ttl")
    win_size = fingerprint.get("window_size")
    proto = ", ".join(fingerprint.get("protocols", []))

    os_guess = guess_os_from_ttl(ttl) if ttl else "Unknown"
    win_size_info = f"Window Size: {win_size}" if win_size else "N/A"

    return f"{os_guess} | {win_size_info} | Protocols: {proto}"
