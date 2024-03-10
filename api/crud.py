from datetime import datetime, timedelta
from typing import Annotated,Any
from sqlalchemy.orm import Session
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
import jwt
from jwt.exceptions import DecodeError
from passlib.context import CryptContext
from fastapi import Depends, HTTPException, status
import models, schemas
import utils 
import config 
from pydantic import EmailStr
import os
import pickle


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login",
                                     scheme_name="JWT")
script_directory = os.path.dirname(os.path.abspath(__file__))


def get_user(db: Session, user_id: int) -> schemas.UserOut:
    user = db.query(models.User).filter(models.User.id == user_id).first()

    if user:
        user_out = schemas.UserOut(
            id=user.id,
            email=user.email,
            fullname=user.fullname,
            is_active=user.is_active,
        )
        return user_out
    else:
        raise HTTPException(status_code=404, detail="User not found")


def get_user_by_email(db: Session, email: EmailStr) -> schemas.User:
    user_data = db.query(models.User).filter(models.User.email == email).first()
    if user_data:
        user = schemas.User(
            id=user_data.id,
            email=user_data.email,
            password=user_data.password,
            fullname=user_data.fullname,
            is_active=user_data.is_active,
            createdAt=user_data.createdAt,
            updatedAt=user_data.updatedAt,
        )
        return user
    else:
        raise HTTPException(status_code=404, detail="User not found")


def delete_user(db: Session, user_id: int):
    user = db.query(models.User).filter(models.User.id == user_id).first()

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User with id {user_id} not found",
        )

    db.delete(user)
    db.commit()

    return {"status": "success", "message": f"User with id {user_id} deleted"}

     
def authenticate_user(db: Session, username: str, password: str):
    user = get_user_by_email(db, username)
    if not user:
        return False
    if not utils.verify_password(password, user.hashed_password):
        return False
    return user


def get_users(db: Session, skip: int = 0, limit: int = 100):
    return db.query(models.User).offset(skip).limit(limit).all()


def get_current_user(db:Session,token: Annotated[str, Depends(oauth2_scheme)]) -> schemas.UserOut:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, config.settings.jwt_secret_key, algorithms=[config.settings.algorithm])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
        token_data = schemas.TokenData(email=email)
    except DecodeError:
        raise credentials_exception
    user = get_user_by_email(db, email=token_data.email)
    if user is None:
        raise credentials_exception
    return user


def get_current_active_user(current_user: Annotated[schemas.User, Depends(get_current_user)]):
    if current_user.is_active == 'disabled':
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user

def get_subject(db: Session, subject_id: int) -> schemas.Subject:
    subject = db.query(models.Subject).filter(models.Subject.id == subject_id).first()

    if subject:
        subject_out = schemas.Subject(
            id=subject.id,
            subject_name=subject.subject_name,
            category = subject.category,
            subject_description=subject.subject_description,
            what_you_learn=subject.what_you_learn,
            subject_topic=subject.subject_topic,
            image_cover=subject.image_cover,
            video_file=subject.video_file,
            language=subject.language,
            createdAt=subject.createdAt,
            updatedAt=subject.updatedAt,
        )
        return subject_out
    else:
        raise HTTPException(status_code=404, detail="Subject not found")


