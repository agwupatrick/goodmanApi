from sqlalchemy import Boolean, Column, ForeignKey, Integer, String,DateTime,Text,Table
from sqlalchemy.orm import relationship
from datetime import datetime
import database


# Define association table for the many-to-many relationship
user_subject_association = Table(
    'user_subject_association',
    database.Base.metadata,
    Column('user_id', Integer, ForeignKey('users.id')),
    Column('subject_id', Integer, ForeignKey('subjects.id'))
)

class User(database.Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    fullname = Column(String, nullable=True)
    role = Column(String,nullable=False)
    email = Column(String, unique=True, index=True)
    password = Column(String)
    is_active = Column(Boolean, default=True)
    createdAt = Column(DateTime, nullable=False, default=datetime.utcnow)
    updatedAt = Column(DateTime, nullable=False, default=datetime.utcnow)

    # many-to-many relationship with Subject
    subjects = relationship("Subject", secondary=user_subject_association, back_populates="users")

    # one -to- many relation with reviews
    reviews = relationship("Review",back_populates="user")

    # One-to-Many relationship with reviews.one subject can have many reviews
    ratings = relationship("Rating", back_populates="user")

    #One-to-Many relationship with Token
    token = relationship("Token", back_populates="user")

    # One-to-Many relationship with Feedback
    feedbacks = relationship("Feedback", back_populates="user")

    # One-to-Many relationship with Enrollment
    enrollments = relationship("Enrollment", back_populates="user")

class Token(database.Base):
    __tablename__ = "token"
    user_id = Column(Integer, ForeignKey("users.id"))
    access_token = Column(String(450),primary_key=True)
    refresh_token = Column(String(450),nullable=False)
    status = Column(Boolean)
    created_date = Column(DateTime, default=datetime.utcnow)
    user = relationship("User", back_populates="token")

class RevokedToken(database.Base):
    __tablename__ = "revoked_tokens"

    jti = Column(String, primary_key=True)
    created_at = Column(DateTime, default=datetime.utcnow)

class Subject(database.Base):
    __tablename__ = "subjects"

    id = Column(Integer, primary_key=True)
    subject_name = Column(String)
    category = Column(String)
    topic = Column(String)
    topic_description = Column(String)
    what_to_learn = Column(String)
    image_cover = Column(String)
    video_file = Column(String)
    language = Column(String)
    createdAt = Column(DateTime, nullable=False, default=datetime.utcnow)
    updatedAt = Column(DateTime, nullable=False, default=datetime.utcnow)

    #  many-to-many relationship with User
    users = relationship("User", secondary=user_subject_association, back_populates="subjects")

    # One-to-Many relationship with reviews.one subject can have many reviews
    reviews = relationship("Review", back_populates="subject")

    # One-to-Many relationship with Subject
    enrollments = relationship("Enrollment", back_populates="subject")

    # One-to-many relationship with ratings. one subject can have many reviews
    ratings = relationship("Rating", back_populates="subject")


class Review(database.Base):
    __tablename__ = "reviews"
    
    id = Column(Integer, primary_key=True)
    subject_id = Column(Integer, ForeignKey("subjects.id"))
    user_id = Column(Integer, ForeignKey("users.id"))
    review_text = Column(String)
    createdAt = Column(DateTime, default=datetime.utcnow)
    
    
    #One-to-Many Relationship between User and Review,One user can have multiple reviews and Each review belongs to only one user.
    user = relationship("User",back_populates="reviews")

    #Many-to-One Relationship between Subject and Review,Many reviews can be associated with one subject and Each review is related to only one subject
    subject = relationship("Subject", back_populates="reviews")


class Rating(database.Base):
    __tablename__ = "ratings"

    rating_id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    subject_id = Column(Integer, ForeignKey("subjects.id"))
    rating = Column(Integer)
    createdAt = Column(DateTime, nullable=False, default=datetime.utcnow)
    updatedAt = Column(DateTime, nullable=False, default=datetime.utcnow)

    #One-to-Many Relationship between User and Rating
    user = relationship("User",back_populates="ratings")
    #Many-to-One Relationship between Subject and Rating
    subject = relationship("Subject", back_populates="ratings")


class Enrollment(database.Base):
    __tablename__ = "enrollments"

    id = Column(Integer, primary_key=True)
    subject_id = Column(Integer, ForeignKey("subjects.id"))
    user_id = Column(Integer, ForeignKey("users.id")) 
    enrolledAt = Column(DateTime, default=datetime.utcnow)

    # Many-to-One relationship with User and Subject [many enrollments can be associated with a single subject]
    subject = relationship("Subject", back_populates="enrollments")

    #one-to-many relationship, as one user can have multiple enrollments but each enrollment belongs to only one user
    user = relationship("User",back_populates="enrollments")


class Feedback(database.Base):
    __tablename__ = "feedbacks"

    feedback_id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    subject = Column(String)
    message = Column(String)
    date = Column(DateTime, default=datetime.utcnow)

    user = relationship("User",back_populates="feedbacks")

class FAQ(database.Base):
    __tablename__ = "faqs"

    id = Column(Integer, primary_key=True)
    question = Column(String, nullable=False)
    answer = Column(Text, nullable=False)
    createdAt = Column(DateTime, default=datetime.utcnow)
    updatedAt = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
