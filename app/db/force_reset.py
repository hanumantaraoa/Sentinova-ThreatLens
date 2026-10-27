from app.core.database import SessionLocal
from app.core.security import get_password_hash
from app.models.all_models import User


def force_reset():
    db = SessionLocal()
    try:
        # Locate the targeted analyst profile row block
        user = db.query(User).filter(User.username == "priya_analyst").first()
        if user:
            print(
                f"Found account record row for: {user.username}. Generating new scrypt block..."
            )
            # Compute a clean, fresh scrypt token string footprint natively
            user.hashed_password = get_password_hash("Password123!")
            db.commit()
            print(
                "✨ Overwrite complete! 'priya_analyst' is now updated to: Password123!"
            )
        else:
            print(
                "⚠️ 'priya_analyst' row not found. Please run: python -m app.db.seed first."
            )
    finally:
        db.close()


if __name__ == "__main__":
    force_reset()
