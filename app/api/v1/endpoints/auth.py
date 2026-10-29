from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.security import verify_password, create_access_token, get_password_hash
from app.api.deps import get_current_user
from app.models.all_models import User, AuditLog
from app.schemas.all_schemas import TokenResponse, UserProfileResponse

router = APIRouter()


@router.post("/login", response_model=TokenResponse)
def login_access_session(
        db: Session = Depends(get_db),
        form_data: OAuth2PasswordRequestForm = Depends()
):
    """
    Validates user credentials against adaptive hashing strategies,
    issuing stateless access and refresh tokens.
    """
    user = db.query(User).filter(User.username == form_data.username).first()

    if not user or not verify_password(form_data.password, user.hashed_password):
        # Operational security protocol: Write failure to system tracking logs
        failed_log = AuditLog(
            action="AUTHENTICATION_FAILED",
            details=f"Failed login attempt for account value: {form_data.username}"
        )
        db.add(failed_log)
        db.commit()

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password combination.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Authentication blocked: User account is currently deactivated."
        )

    # Issue stateless JSON Web Tokens
    access_token = create_access_token(data={"sub": user.username})

    # Append successful access signatures into the append-only audit database table
    success_log = AuditLog(
        actor_username=user.username,
        action="AUTHENTICATION_SUCCESS",
        details="Access session tokens generated cleanly."
    )
    db.add(success_log)
    db.commit()

    return {
        "access_token": access_token,
        "refresh_token": "REFRESH_TOKEN_ROTATION_STUB_IMPLEMENTATION",
        "token_type": "bearer"
    }


@router.get("/me", response_model=UserProfileResponse)
def read_active_profile(current_user: User = Depends(get_current_user)):
    """Surfaces active account authorization metadata back to the client interface layer."""
    return current_user
