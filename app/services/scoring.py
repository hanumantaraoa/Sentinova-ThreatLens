from app.models.all_models import Indicator, IOCType


def calculate_severity_score(indicator: Indicator, base_feed_confidence: int) -> int:
    """
    Computes a reproducible severity score (0-100) using source attributes,
    confidence metrics, and indicator categorization maps.
    """
    score = base_feed_confidence

    # Critical threat vector parameter shifts
    if indicator.type == IOCType.HASH_SHA256:
        score += 20
    elif indicator.type == IOCType.URL or indicator.type == IOCType.DOMAIN:
        score += 10

    # Enforce ecosystem absolute scale limits
    return min(max(score, 0), 100)
