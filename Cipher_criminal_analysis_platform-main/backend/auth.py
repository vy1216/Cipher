import os
from datetime import datetime, timedelta, timezone

from dotenv import load_dotenv
from jose import jwt, JWTError
from passlib.context import CryptContext
from sqlalchemy.orm import Session
from fastapi import HTTPException

from models import User


load_dotenv()


# ============================================================
# PASSWORD HASHING
# ============================================================

pwd_context = CryptContext(
    schemes=["bcrypt"],
    deprecated="auto"
)


# ============================================================
# JWT CONFIGURATION
# ============================================================

SECRET_KEY = os.getenv("SECRET_KEY", "cipher_secret_key_super_secure_default_12345")

ALGORITHM = "HS256"

ACCESS_TOKEN_EXPIRE_MINUTES = 60


# ============================================================
# PASSWORD FUNCTIONS
# ============================================================

def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(
    password: str,
    password_hash: str
) -> bool:

    return pwd_context.verify(
        password,
        password_hash
    )


# ============================================================
# USER CREATION
# ============================================================

def create_user(
    db: Session,
    full_name: str,
    email: str,
    password: str,
    role: str = "INVESTIGATOR"
):

    existing_user = (
        db.query(User)
        .filter(User.email == email)
        .first()
    )

    if existing_user:
        return None

    user = User(
        full_name=full_name,
        email=email,
        password_hash=hash_password(password),
        role=role
    )

    db.add(user)

    db.commit()

    db.refresh(user)

    return user


# ============================================================
# USER AUTHENTICATION
# ============================================================

def authenticate_user(
    db: Session,
    email: str,
    password: str
):

    user = (
        db.query(User)
        .filter(User.email == email)
        .first()
    )

    if not user:
        return None

    if not verify_password(
        password,
        user.password_hash
    ):
        return None

    return user


# ============================================================
# CREATE JWT ACCESS TOKEN
# ============================================================

def create_access_token(user: User):

    expire = (
        datetime.now(timezone.utc)
        + timedelta(
            minutes=ACCESS_TOKEN_EXPIRE_MINUTES
        )
    )

    payload = {
        "sub": str(user.id),
        "email": user.email,
        "role": user.role,
        "exp": expire
    }

    return jwt.encode(
        payload,
        SECRET_KEY,
        algorithm=ALGORITHM
    )


# ============================================================
# DECODE JWT ACCESS TOKEN
# ============================================================

def decode_access_token(token: str):

    try:

        payload = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=[ALGORITHM]
        )

        return payload

    except JWTError:

        return None


# ============================================================
# RBAC
# ROLE BASED ACCESS CONTROL
# ============================================================

def check_role(
    user: User,
    allowed_roles: list[str]
):

    if user.role not in allowed_roles:

        raise HTTPException(
            status_code=403,
            detail="You do not have permission to access this resource"
        )

    return user