from passlib.context import CryptContext
from datetime import datetime, timedelta
from typing import Union, Any
import jwt
from jwt.exceptions import InvalidTokenError
import os
from datetime import datetime
import config



ACCESS_TOKEN_EXPIRE_MINUTES = config.settings.access_token_expire_minutes
REFRESH_TOKEN_EXPIRE_MINUTES = config.settings.refresh_token_expire_minutes
ALGORITHM = config.settings.algorithm
JWT_SECRET_KEY = config.settings.jwt_secret_key
JWT_REFRESH_SECRET_KEY = config.settings.jwt_refresh_secret_key

password_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def get_hashed_password(password: str) -> str:
    return password_context.hash(password)


def verify_password(password: str, hashed_pass: str) -> bool:
    return password_context.verify(password, hashed_pass)

def validate_password(password: str) -> bool:
    """
    Validates the strength of the provided password.

    Args:
        password: The password to validate.

    Returns:
        True if the password is strong, False otherwise.
    """

    # Check minimum password length
    if len(password) < 8:
        return False

    # Check for uppercase letters
    if not any(c.isupper() for c in password):
        return False

    # Check for lowercase letters
    if not any(c.islower() for c in password):
        return False

    # Check for digits
    if not any(c.isdigit() for c in password):
        return False

    # Additional checks for special characters, word lists, etc. can be added here

    return True

def create_access_token(subject: Union[str, Any], expires_delta: int  = None) -> str:
    if expires_delta is not None:
        expires_delta = datetime.utcnow() + expires_delta
    else:
        expires_delta = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    
    to_encode = {"exp": expires_delta, "sub": str(subject)}
    encoded_jwt = jwt.encode(to_encode, JWT_SECRET_KEY, ALGORITHM)
    return encoded_jwt

def create_refresh_token(subject: Union[str, Any], expires_delta: int = None) -> str:
    if expires_delta is not None:
        expires_delta = datetime.utcnow() + expires_delta
    else:
        expires_delta = datetime.utcnow() + timedelta(minutes=REFRESH_TOKEN_EXPIRE_MINUTES)
    
    to_encode = {"exp": expires_delta, "sub": str(subject)}
    encoded_jwt = jwt.encode(to_encode, JWT_REFRESH_SECRET_KEY, ALGORITHM)
    return encoded_jwt

# Function to handle filename collisions asynchronously
async def handle_collision_async(file_path: str) -> str:
    if os.path.exists(file_path):
        base, ext = os.path.splitext(file_path)
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        file_path = f"{base}_{timestamp}{ext}"
    return file_path



