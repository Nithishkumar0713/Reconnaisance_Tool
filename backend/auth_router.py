"""
auth_router.py — FastAPI router for /auth/send-otp, /auth/register and /auth/login endpoints.
"""

from fastapi import APIRouter, Depends, HTTPException, status, Request
from pydantic import BaseModel, EmailStr, field_validator
from sqlalchemy.orm import Session

from database import get_db
from models import User, LoginHistory
from auth import hash_password, verify_password, create_access_token, get_current_user
from email_service import store_otp, verify_otp, send_otp_email, send_password_reset_otp_email

router = APIRouter(prefix="/auth", tags=["auth"])


def _validate_password_strength(v: str) -> str:
    """Shared password-strength rule, used by both registration and password reset."""
    import re
    errors = []
    if len(v) < 8:
        errors.append("at least 8 characters")
    if len(v) > 72:
        raise ValueError("Password cannot be longer than 72 characters.")
    if not re.search(r"[A-Z]", v):
        errors.append("one uppercase letter")
    if not re.search(r"[0-9]", v):
        errors.append("one number")
    if not re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\\|,.<>\/?`~]", v):
        errors.append("one special character")
    if errors:
        raise ValueError("Password must contain: " + ", ".join(errors) + ".")
    return v



class SendOtpRequest(BaseModel):
    """Request body for sending an OTP to an email address."""
    email: EmailStr
    full_name: str

    @field_validator("full_name")
    @classmethod
    def name_not_empty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("Full name cannot be empty.")
        return v.strip()


class RegisterRequest(BaseModel):
    """Request body for creating a new account. OTP field is now required."""
    full_name: str
    email: EmailStr
    password: str
    otp: str

    @field_validator("password")
    @classmethod
    def password_strength(cls, v: str) -> str:
        return _validate_password_strength(v)

    @field_validator("full_name")
    @classmethod
    def name_not_empty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("Full name cannot be empty.")
        return v.strip()

    @field_validator("otp")
    @classmethod
    def otp_format(cls, v: str) -> str:
        v = v.strip()
        if not v.isdigit() or len(v) != 6:
            raise ValueError("OTP must be exactly 6 digits.")
        return v


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class ForgotPasswordRequest(BaseModel):
    """Request body for triggering a password-reset OTP email."""
    email: EmailStr


class ResetPasswordRequest(BaseModel):
    """Request body for completing a password reset with a verified OTP."""
    email: EmailStr
    otp: str
    new_password: str

    @field_validator("new_password")
    @classmethod
    def password_strength(cls, v: str) -> str:
        return _validate_password_strength(v)

    @field_validator("otp")
    @classmethod
    def otp_format(cls, v: str) -> str:
        v = v.strip()
        if not v.isdigit() or len(v) != 6:
            raise ValueError("OTP must be exactly 6 digits.")
        return v


class AuthResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user_id: int
    full_name: str
    email: str



@router.post("/send-otp", status_code=200)
def send_otp_endpoint(body: SendOtpRequest, db: Session = Depends(get_db)):
    """
    Generate a 6-digit OTP and email it to the provided address.
    Rejects if email is already registered or if cooldown hasn't elapsed.
    """
    existing = db.query(User).filter(User.email == body.email).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An account with this email already exists.",
        )

    try:
        otp = store_otp(body.email)
        send_otp_email(body.email, otp, body.full_name)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail=str(e))
    except RuntimeError as e:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(e))

    return {"message": "Verification code sent. Please check your inbox (and spam folder)."}


@router.post("/register", response_model=AuthResponse, status_code=status.HTTP_201_CREATED)
def register(body: RegisterRequest, request: Request, db: Session = Depends(get_db)):
    """
    Register a new user account.
    Requires a valid OTP previously sent via /auth/send-otp.
    Returns a JWT access token immediately so the user is logged in straight away.
    """
    try:
        verify_otp(body.email, body.otp)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    existing = db.query(User).filter(User.email == body.email).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An account with this email already exists.",
        )

    user = User(
        full_name=body.full_name,
        email=body.email,
        password_hash=hash_password(body.password),
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    ip = request.client.host if request.client else "127.0.0.1"
    ua = request.headers.get("user-agent", "Unknown Browser")
    login_entry = LoginHistory(
        user_id=user.id,
        ip_address=ip,
        user_agent=ua[:250],
        session_type="Account Created & Login"
    )
    db.add(login_entry)
    db.commit()

    token = create_access_token(user.id, user.email, client_ip=ip, user_agent=ua)
    return AuthResponse(
        access_token=token,
        user_id=user.id,
        full_name=user.full_name,
        email=user.email,
    )


@router.post("/login", response_model=AuthResponse)
def login(body: LoginRequest, request: Request, db: Session = Depends(get_db)):
    """
    Authenticate an existing user.
    Returns a JWT access token on success.
    """
    user = db.query(User).filter(User.email == body.email).first()

    if not user or not verify_password(body.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password.",
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This account has been deactivated.",
        )

    ip = request.client.host if request.client else "127.0.0.1"
    ua = request.headers.get("user-agent", "Unknown Browser")
    login_entry = LoginHistory(
        user_id=user.id,
        ip_address=ip,
        user_agent=ua[:250],
        session_type="Web Login"
    )
    db.add(login_entry)
    db.commit()

    token = create_access_token(user.id, user.email, client_ip=ip, user_agent=ua)
    return AuthResponse(
        access_token=token,
        user_id=user.id,
        full_name=user.full_name,
        email=user.email,
    )


@router.post("/forgot-password", status_code=200)
def forgot_password(body: ForgotPasswordRequest, db: Session = Depends(get_db)):
    """
    Send a password-reset OTP to an existing account's email.
    Reveals whether the email is registered (matches this app's existing
    /auth/send-otp behavior, which does the same for registration) rather
    than a generic "if this email exists" response.
    """
    user = db.query(User).filter(User.email == body.email).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No account found with this email address.",
        )

    try:
        otp = store_otp(body.email)
        send_password_reset_otp_email(body.email, otp, user.full_name)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail=str(e))
    except RuntimeError as e:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(e))

    return {"message": "A password reset code has been sent. Please check your inbox (and spam folder)."}


@router.post("/reset-password", status_code=200)
def reset_password(body: ResetPasswordRequest, db: Session = Depends(get_db)):
    """
    Complete a password reset: verify the OTP sent via /auth/forgot-password,
    then update the account's password hash. Does not issue a token — the
    user signs in fresh with the new password, same as after registration.
    """
    try:
        verify_otp(body.email, body.otp)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    user = db.query(User).filter(User.email == body.email).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No account found with this email address.",
        )

    user.password_hash = hash_password(body.new_password)
    db.commit()

    return {"message": "Password reset successful. Please sign in with your new password."}


@router.get("/me", response_model=AuthResponse)
def get_me(current_user: User = Depends(get_current_user)):
    """
    Get profile information of the currently authenticated user.
    """
    return AuthResponse(
        access_token="",
        user_id=current_user.id,
        full_name=current_user.full_name,
        email=current_user.email,
    )

