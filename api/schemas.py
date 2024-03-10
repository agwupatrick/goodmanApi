from pydantic import ConfigDict,BaseModel,EmailStr
from datetime import datetime
from typing import List,Optional

class Token(BaseModel):
    access_token: str
    refresh_token: str
    user_id: int

class TokenData(BaseModel):
    user_id: str| None = None
    access_token:str
    refresh_token:str
    status: bool
    created_date: datetime


class UserOut(BaseModel):
    id: int
    email: EmailStr
    fullname: str | None = None
    is_active: bool | None = None

class User(UserOut):
    password: str
    createdAt: datetime | None = None
    updatedAt: datetime | None = None


class UserCreate(BaseModel):
    email: EmailStr
    password:str
    fullname:str | None = None
    role:str
    is_active: bool | None = None
    createdAt: datetime | None = None
    updatedAt: datetime | None = None


class UserIn(BaseModel):
    email: EmailStr
    password: str

class UserInDB(User):
    hashed_password: str

class ChangePassword(BaseModel):
    email: EmailStr
    old_password:str
    new_password:str


class SubjectBase(BaseModel):
    subject_name: str
    category:str
    topic: str
    topic_description: str
    what_to_learn: str
    image_cover: str
    video_file: str
    language: str

class SubjectCreate(SubjectBase):
    pass

class SubjectUpdate(SubjectBase):
    pass

class Subject(SubjectBase):
    id: int
    createdAt: datetime
    updatedAt:datetime
    model_config = ConfigDict(from_attributes=True)


class ReviewBase(BaseModel):
    id:int
    Subject_id:int
    user_id:int
    review_text:str
    createdAt:datetime

class ReviewCreate(ReviewBase):
    pass

class ReviewUpdate(ReviewBase):
    pass

class ReviewOut(ReviewBase):
    id: int
    createdAt: datetime
    model_config = ConfigDict(from_attributes=True)



class RatingBase(BaseModel):
    rating: int

class RatingCreate(RatingBase):
    user_id: int
    subject_id: int

class Rating(RatingBase):
    rating_id: int
    user_id: int
    subject_id: int
    createdAt: datetime
    updatedAt: datetime 
    model_config = ConfigDict(from_attributes=True)


class EnrollmentBase(BaseModel):
    subject_id: int
    user_id: int
    enrolledAt: datetime

class EnrollmentCreate(EnrollmentBase):
    pass

class EnrollmentUpdate(EnrollmentBase):
    pass

class EnrollmentOut(EnrollmentBase):
    id: int
    model_config = ConfigDict(from_attributes=True)

class FeedbackBase(BaseModel):
    user_id: int
    subject: str
    message: str
    date: datetime

class FeedbackUpdate(FeedbackBase):
    pass

class FeedbackCreate(FeedbackBase):
    pass

class FeedbackOut(FeedbackBase):
    feedback_id: int
    model_config = ConfigDict(from_attributes=True)

class FAQBase(BaseModel):
    question: str
    answer: str

class FAQCreate(FAQBase):
    pass

class FAQUpdate(FAQBase):
    pass

class FAQOut(FAQBase):
    id: int
    createdAt: datetime
    updatedAt: datetime





    
