from fastapi import Depends, FastAPI, HTTPException,Request,status,Query,Header,File, UploadFile
from fastapi.security import OAuth2PasswordBearer,OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from datetime import datetime, timedelta
from fastapi.responses import JSONResponse,Response
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError
from sqlalchemy import select, insert
from sqlalchemy import text,insert
from datetime import datetime
from typing import Any,Union,Optional,Annotated
from datetime import datetime, timedelta
from pydantic import ValidationError
import crud,schemas,models
import database 
import os
import jwt
import aiofiles
import utils
import logging
import secrets
import string



models.database.Base.metadata.create_all(bind=database.engine)
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

reuseable_oauth = OAuth2PasswordBearer(
    tokenUrl="/authenticate",
    scheme_name="JWT"
)

# In-memory cache for user data
user_cache = {}

app = FastAPI()
origins = [
    "http://127.0.0.1:8000/",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,  # Add your React app's URL here
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Dependency
def get_db():
    db = database.SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Create new user endpoint
@app.post("/createUser", response_model=schemas.UserOut, status_code=status.HTTP_201_CREATED)
def create_user(user: schemas.UserCreate, db: Session = Depends(get_db)) -> JSONResponse:
    hashed_password = utils.get_hashed_password(user.password)
    existing_user = db.query(models.User).filter_by(email=user.email).first()
    if existing_user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already exists")

    try:
        new_user = models.User(fullname=user.fullname, role=user.role, email=user.email, password=hashed_password)
        db.add(new_user)
        db.commit()
        db.refresh(new_user)

        return new_user

    except IntegrityError as e:
        logger.error(f"IntegrityError: {e}")
        db.rollback()
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Failed to create user")

# User authentication endpoint
@app.post("/authenticate", summary="Create access and refresh tokens for user", response_model=schemas.Token)
async def authenticate(payload: OAuth2PasswordRequestForm = Depends(),db: Session = Depends(get_db)) -> dict[str, str]:
    # Log the login attempt
    logger.info(f"Login attempt from email: {payload.username}")

    try:
        user = crud.get_user_by_email(db=db, email=payload.username)
        if user is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="User does not exist",
            )

        hashed_pass = user.password
        if not utils.verify_password(payload.password, hashed_pass):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Incorrect credentials",
            )
        # Use create_access_token() and create_refresh_token() to create our
        # access and refresh tokens
        access_token = utils.create_access_token(subject=payload.username)
        refresh_token = utils.create_refresh_token(subject=payload.username)
        # Create and save token data
        token_db = models.Token(user_id=user.id, access_token=access_token, refresh_token=refresh_token, status=True)
        db.add(token_db)
        db.commit()
        db.refresh(token_db)
        # Log successful login
        logger.info(f"Login successful for user: {user.email}")
        return {"access_token": access_token, "refresh_token": refresh_token,"token_type": "bearer"}
    except Exception as e:
        # Log the error
        logger.error(f"Login failed for email: {payload.username}: {e}")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Login failed for wrong email or password")


async def get_current_user(token: str = Depends(reuseable_oauth), db: Session = Depends(get_db)) -> schemas.UserOut:
    try:
        payload = jwt.decode(token, utils.JWT_SECRET_KEY, algorithms=[utils.ALGORITHM])
        user_email: str = payload.get("sub")
        if user_email is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )
        user = db.query(models.User).filter(models.User.email == user_email).first()
        if user is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return schemas.UserOut(
            id=user.id,
            email=user.email,
            fullname=user.fullname,
            is_active=user.is_active,
        )
    except jwt.exceptions.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

async def get_current_active_user(current_user: schemas.UserOut = Depends(get_current_user)):
    if not current_user.is_active:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user

# User change password endpoint
@app.post('/change-password')
def change_password(request:schemas.ChangePassword, db: Session = Depends(get_db),user: schemas.User = Depends(get_current_active_user)):
    try:
        user = db.query(models.User).filter(models.User.email == request.email).first()
        if not user:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="User not found")

        if not utils.verify_password(request.old_password,user.password):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid old password")

        if not utils.validate_password(request.new_password):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="New password does not meet minimum requirements")

        # Update password
        user.password = utils.get_hashed_password(request.new_password)
        db.commit()
        # Log successful password change
        logger.info(f"User: {user.email} successfully changed password")
        return {"message": "Password changed successfully"}
    except Exception as e:
        # Log the error
        logger.error(f"Error changing password: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error changing password")


@app.post('/logout')
def logout(current_user: schemas.UserOut = Depends(get_current_user), db: Session = Depends(get_db)):
    try:
        # Update the status of the token
        token = db.query(models.Token).filter(models.Token.user_id == current_user.id).first()
        if not token:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Token not found")
        
        token.status = False
        db.commit()
        
        logger.info(f"User '{current_user.id}' logged out successfully")
        return {"message": "Logout Successful"}
    except Exception as e:
        logger.error(f"Failed to logout: {e}")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Failed to logout")


#endpoint to get users from 1 to 100
@app.get("/users")
async def get_users(
    current_user: schemas.UserOut = Depends(get_current_user),
    db: Session = Depends(get_db),
    page: int = Query(default=1, ge=1),
    per_page: Optional[int] = Query(default=10, ge=1, le=100),
    sort_by: str = Query(default="id", allowed=["id", "email", "createdAt"]),
    sort_order: str = Query(default="asc", allowed=["asc", "desc"]),
    filter_by: str = Query(default=None),
):
    if per_page is None:
        per_page = 10  # Default value if not provided or None
    
    offset = (page - 1) * per_page
    cache_key = f"users_page_{page}_per_page_{per_page}"
    cached_users = user_cache.get(cache_key)

    if not cached_users:
        query = db.query(models.User)

        if filter_by:
            try:
                filter_by_field, filter_value = filter_by.split(":")
                query = query.filter(getattr(models.User, filter_by_field) == filter_value)
            except ValueError:
                raise HTTPException(status_code=400, detail="Invalid filter format.")
        order_by_clause = text(f"{sort_by} {sort_order}")
        query = query.order_by(order_by_clause)
        users = query.limit(per_page).offset(offset).all()
        user_cache[cache_key] = users

    # Return cached or retrieved users
    return users

#endpoint to get single user data
@app.get("/user/{user_id}", response_model= schemas.UserOut)
def read_user(current_user: schemas.UserOut = Depends(get_current_user), db: Session = Depends(get_db)):
    db_user = crud.get_user(db, user_id=current_user.id)
    if db_user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return db_user

#endpoint to deativate user account
@app.put("/deactivate-user/{user_id}")
def suspend_user(user_id: int,db: Session = Depends(get_db),current_user: schemas.UserOut = Depends(get_current_user)):
    # Retrieve the user from the database
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    # Check if the user is already suspended
    if not user.is_active:
        raise HTTPException(status_code=400, detail="User is already suspended")
    # Suspend the user account
    user.is_active = False
    user.updatedAt = datetime.utcnow()
    db.commit()
    return {"message": "User account suspended successfully"}

#endpoint to reactivate user account
@app.put("/reactivate-user/{user_id}")
def reactivate_user(user_id: int,db: Session = Depends(get_db),current_user: schemas.UserOut = Depends(get_current_user)):
    # Retrieve the user from the database
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    # Check if the user is already active
    if user.is_active:
        raise HTTPException(status_code=400, detail="User is already active")
    # Reactivate the user account
    user.is_active = True
    user.updatedAt = datetime.utcnow()
    db.commit()
    return {"message": "User account reactivated successfully"}

# Endpoint to create new course
@app.post("/create-tutorial", status_code=201)
async def create_subject_and_associate_user(
    subject_name: str,
    category: str,
    topic: str,
    topic_description: str,
    what_to_learn: str,
    image_cover: UploadFile = File(...),
    video_file: UploadFile = File(...),
    db: Session = Depends(get_db),
    user: schemas.User = Depends(get_current_user)
):
    try:
        # Check if videos folder exists, if not create it
        videos_folder = "videos"
        if not os.path.exists(videos_folder):
            os.makedirs(videos_folder)

        # Check if images folder exists, if not create it
        images_folder = "images"
        if not os.path.exists(images_folder):
            os.makedirs(images_folder)

        # Save the video file
        video_path = f"{videos_folder}/{video_file.filename}"
        video_path = await utils.handle_collision_async(video_path)  # Handle filename collision for video file
        async with aiofiles.open(video_path, "wb") as buffer:
            await buffer.write(await video_file.read())

        # Save the image file
        image_path = f"{images_folder}/{image_cover.filename}"
        image_path = await utils.handle_collision_async(image_path)  # Handle filename collision for image file
        async with aiofiles.open(image_path, "wb") as buffer:
            await buffer.write(await image_cover.read())

        # Create the new subject
        new_subject = models.Subject(
            subject_name=subject_name,
            category=category,
            topic=topic,
            topic_description=topic_description,
            what_to_learn=what_to_learn,
            image_cover=image_path,
            video_file=video_path,
            language="English",  # Sample language
            createdAt=datetime.utcnow(),
            updatedAt=datetime.utcnow()
        )

        # Add the subject to the database
        db.add(new_subject)
        db.commit()
        db.refresh(new_subject)

        logger.info("New subject created successfully.")

        # Associate the subject with the user
        stmt = insert(models.user_subject_association).values(user_id=user.id, subject_id=new_subject.id)
        db.execute(stmt)
        db.commit()

        logger.info("Subject associated with user successfully.")

        return new_subject

    except Exception as e:
        logger.error(f"Failed to create subject or associate with user: {str(e)}")
        return JSONResponse(content={"error": "Failed to create subject or associate with user"}, status_code=500)
    
#end point to fetch list of subjects from 1 - 100
@app.get("/tutorials", response_model=list[schemas.Subject])
def get_subjects(
    page: int = Query(default=1, ge=1),
    per_page: int = Query(default=10, ge=1, le=100),
    db: Session = Depends(get_db)
):
    try:
        offset = (page - 1) * per_page
        subjects = db.query(models.Subject).limit(per_page).offset(offset).all()
        return subjects
    except Exception as e:
        logger.error(f"Failed to retrieve subjects: {str(e)}")
        return JSONResponse(content={"error": "Failed to retrieve subjects"}, status_code=500)

#endpoint to fetch a subject with a specific id
@app.get("/tutorial/{id}", status_code=200)
def get_subject(id: int, db: Session = Depends(get_db)):
    db_subject = db.query(models.Subject).filter(models.Subject.id == id).first()
    if db_subject is None:
        raise HTTPException(status_code=404, detail=f"Subject with id {id} not found")
    return db_subject

#endpoint to fetch subjects uploaded by a user
@app.get("/user/{user_id}/tutorials", response_model=list[schemas.Subject])
def get_subjects_by_user(user_id: int, db: Session = Depends(get_db)):
    try:
        user = db.query(models.User).filter(models.User.id == user_id).first()
        if not user:
            raise HTTPException(status_code=404, detail=f"User with id {user_id} not found")

        # Fetch all subjects uploaded by the user
        subjects = db.query(models.Subject).join(models.user_subject_association).filter(models.user_subject_association.c.user_id == user_id).all()

        return subjects

    except Exception as e:
        logger.error(f"Failed to fetch subjects uploaded by user: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to fetch subjects uploaded by user")

#endpoints to get subjects by category
@app.get("/tutorials/{category}", response_model=list[schemas.Subject])
def get_subjects_by_category(category: str, db: Session = Depends(get_db)):
    try:
        # Fetch subjects by category
        subjects = db.query(models.Subject).filter(models.Subject.category == category).all()

        if not subjects:
            raise HTTPException(status_code=404, detail=f"No subjects found for category: {category}")

        return subjects

    except Exception as e:
        logger.error(f"Failed to fetch subjects by category: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to fetch subjects by category")


# endpoint to delete a subject with an id
@app.delete("/tutorial/{id}", status_code=204)
def delete_subject(id: int, db: Session = Depends(get_db)):
    db_subject = db.query(models.Subject).filter(models.Subject.id == id).first()
    if db_subject is None:
        raise HTTPException(status_code=404, detail=f"Subject with id {id} not found")
    else:
        db.delete(db_subject)
        db.commit()
    return None

#endpoint to update a subject
@app.put("/tutorial/{id}", status_code=200)
def update_subject(id: int, subject_update: schemas.SubjectUpdate, db: Session = Depends(get_db)):
    # Retrieve the subject from the database
    db_subject = db.query(models.Subject).filter(models.Subject.id == id).first()
    if db_subject is None:
        raise HTTPException(status_code=404, detail=f"Subject with id {id} not found")

    # Update the subject attributes
    for attr, value in subject_update.dict().items():
        if hasattr(db_subject, attr):
            setattr(db_subject, attr, value)

    # Commit changes to the database
    db.commit()
    db.refresh(db_subject)
    
    return db_subject

# Create a review
@app.post("/reviews/", response_model=schemas.ReviewOut)
def create_review(review: schemas.ReviewCreate,user_id:int,subject_id, db: Session = Depends(get_db)):
    db_review = models.Review(**review.dict(),user_id=user_id,subject_id=subject_id)
    db.add(db_review)
    db.commit()
    db.refresh(db_review)
    return db_review

#endpoint to get a review made by a user on a subject tutorial
@app.get("/review/{user_id}/{subject_id}", response_model=schemas.ReviewOut)
def get_review_by_user_and_subject(user_id: int, subject_id: int, db: Session = Depends(get_db)):
    review = db.query(models.Review).filter(models.Review.user_id == user_id, models.Review.subject_id == subject_id).first()
    if review is None:
        raise HTTPException(status_code=404, detail="Review not found")
    return review

#get reviews made on a subject
@app.get("/reviews/{subject_id}", response_model=list[schemas.ReviewOut])
def get_reviews_by_subject(subject_id: int, db: Session = Depends(get_db)):
    reviews = db.query(models.Review).filter(models.Review.subject_id == subject_id).all()
    if not reviews:
        raise HTTPException(status_code=404, detail="No reviews found for this subject")
    return reviews

# Update a review
@app.put("/reviews/{review_id}", response_model=schemas.ReviewOut)
def update_review(review_id: int, review: schemas.ReviewUpdate, db: Session = Depends(get_db)):
    db_review = db.query(models.Review).filter(models.Review.id == review_id).first()
    if db_review is None:
        raise HTTPException(status_code=404, detail="Review not found")
    for attr, value in review.dict().items():
        setattr(db_review, attr, value)
    db.commit()
    db.refresh(db_review)
    return db_review

# Delete a review
@app.delete("/reviews/{review_id}")
def delete_review(review_id: int, db: Session = Depends(get_db)):
    db_review = db.query(models.Review).filter(models.Review.id == review_id).first()
    if db_review is None:
        raise HTTPException(status_code=404, detail="Review not found")
    db.delete(db_review)
    db.commit()
    return {"message": "Review deleted successfully"}

#endpoint to create user rating of a subject course
@app.post("/ratings/", response_model=schemas.Rating)
def create_rating(rating_create: schemas.RatingCreate,user_id,subject_id, db: Session = Depends(get_db)):
    try:
        new_rating = models.Rating(**rating_create.dict(),user_id=user_id,subject_id=subject_id)
        db.add(new_rating)
        db.commit()
        db.refresh(new_rating)
        return new_rating
    except Exception as e:
        logger.error(f"Failed to create rating: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to create rating")
   
#get a rating made on a subject
@app.get("/ratings/{subject_id}", response_model=list[schemas.Rating])
def get_ratings_by_subject(subject_id: int, db: Session = Depends(get_db)):
    ratings = db.query(models.Rating).filter(models.Rating.subject_id == subject_id).all()
    if not ratings:
        raise HTTPException(status_code=404, detail="No ratings found for this subject")
    return ratings

#endpoint to get a rating made by a user on a subject
@app.get("/ratings/{subject_id}/{user_id}", response_model=schemas.Rating)
def get_rating_by_user_and_subject(subject_id: int, user_id: int, db: Session = Depends(get_db)):
    rating = db.query(models.Rating).filter(models.Rating.subject_id == subject_id, models.Rating.user_id == user_id).first()
    if not rating:
        raise HTTPException(status_code=404, detail="Rating not found for this user and subject")
    return rating


@app.put("/ratings/{rating_id}", response_model=schemas.Rating)
def update_rating(rating_id: int, rating_update: schemas.RatingCreate, db: Session = Depends(get_db)):
    try:
        db_rating = db.query(models.Rating).filter(models.Rating.rating_id == rating_id).first()
        if not db_rating:
            raise HTTPException(status_code=404, detail=f"Rating with id {rating_id} not found")
        for var, value in vars(rating_update).items():
            setattr(db_rating, var, value)
        db.commit()
        db.refresh(db_rating)
        return db_rating
    except Exception as e:
        logger.error(f"Failed to update rating: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to update rating")

@app.delete("/ratings/{rating_id}", status_code=204)
def delete_rating(rating_id: int, db: Session = Depends(get_db)):
    try:
        db_rating = db.query(models.Rating).filter(models.Rating.rating_id == rating_id).first()
        if not db_rating:
            raise HTTPException(status_code=404, detail=f"Rating with id {rating_id} not found")
        db.delete(db_rating)
        db.commit()
        return Response(status_code=204)
    except Exception as e:
        logger.error(f"Failed to delete rating: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to delete rating")

# Create an enrollment
@app.post("/enrollments/", response_model=schemas.EnrollmentOut)
def create_enrollment(enrollment: schemas.EnrollmentCreate,user_id,subject_id, db: Session = Depends(get_db)):
    db_enrollment = models.Enrollment(**enrollment.dict(),user_id=user_id,subject_id=subject_id)
    db.add(db_enrollment)
    db.commit()
    db.refresh(db_enrollment)
    return db_enrollment

#endpoint to get all subject courses enrolled by a user
@app.get("/user/{user_id}/enrolled-subjects", response_model=list[schemas.Subject])
def get_enrolled_subjects_by_user(user_id: int, db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")

    enrolled_subjects = [enrollment.subject for enrollment in user.enrollments]
    return enrolled_subjects

#endpoint to get a single subject enrolled by a user
@app.get("/user/{user_id}/enrolled-subject/{subject_id}", response_model=schemas.Subject)
def get_enrolled_subject_by_user(user_id: int, subject_id: int, db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    
    subject = db.query(models.Subject).filter(models.Subject.id == subject_id).first()
    if subject is None:
        raise HTTPException(status_code=404, detail="Subject not found")

    enrolled_subjects = [enrollment.subject for enrollment in user.enrollments]
    if subject not in enrolled_subjects:
        raise HTTPException(status_code=404, detail="Subject not enrolled by the user")
    
    return subject

#endpoint to get all users who enrolled on a subject course
@app.get("/subject/{subject_id}/enrolled-users", response_model=list[schemas.User])
def get_enrolled_users_by_subject(subject_id: int, db: Session = Depends(get_db)):
    subject = db.query(models.Subject).filter(models.Subject.id == subject_id).first()
    if subject is None:
        raise HTTPException(status_code=404, detail="Subject not found")

    enrolled_users = [enrollment.user for enrollment in subject.enrollments]
    return enrolled_users

# Update an enrollment
@app.put("/enrollments/{enrollment_id}", response_model=schemas.EnrollmentOut)
def update_enrollment(enrollment_id: int, enrollment: schemas.EnrollmentUpdate, db: Session = Depends(get_db)):
    db_enrollment = db.query(models.Enrollment).filter(models.Enrollment.id == enrollment_id).first()
    if db_enrollment is None:
        raise HTTPException(status_code=404, detail="Enrollment not found")
    for attr, value in enrollment.dict().items():
        setattr(db_enrollment, attr, value)
    db.commit()
    db.refresh(db_enrollment)
    return db_enrollment

# Delete an enrollment
@app.delete("/enrollments/{enrollment_id}")
def delete_enrollment(enrollment_id: int, db: Session = Depends(get_db)):
    db_enrollment = db.query(models.Enrollment).filter(models.Enrollment.id == enrollment_id).first()
    if db_enrollment is None:
        raise HTTPException(status_code=404, detail="Enrollment not found")
    db.delete(db_enrollment)
    db.commit()
    return {"message": "Enrollment deleted successfully"}


# Create a feedback
@app.post("/feedbacks/", response_model=schemas.FeedbackOut)
def create_feedback(feedback: schemas.FeedbackCreate, db: Session = Depends(get_db)):
    db_feedback = models.Feedback(**feedback.dict())
    db.add(db_feedback)
    db.commit()
    db.refresh(db_feedback)
    return db_feedback

# Read a feedback by ID
@app.get("/feedbacks/{feedback_id}", response_model=schemas.FeedbackOut)
def read_feedback(feedback_id: int, db: Session = Depends(get_db)):
    db_feedback = db.query(models.Feedback).filter(models.Feedback.feedback_id == feedback_id).first()
    if db_feedback is None:
        raise HTTPException(status_code=404, detail="Feedback not found")
    return db_feedback

#endpoint to get all feedbacks from a particular user
@app.get("/user/{user_id}/feedbacks", response_model=list[schemas.FeedbackOut])
def get_feedbacks_by_user(user_id: int, db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")

    feedbacks = user.feedbacks
    return feedbacks

#endpoint to get a feedback within a date range
@app.get("/feedbacks", response_model=list[schemas.FeedbackOut])
def get_feedbacks_by_date_range(start_date: datetime = Query(None, alias="startDate"),
                                end_date: datetime = Query(None, alias="endDate"),
                                db: Session = Depends(get_db)):
    if start_date is None or end_date is None:
        raise HTTPException(status_code=400, detail="Both start date and end date are required")

    feedbacks = db.query(models.Feedback).filter(models.Feedback.date >= start_date,
                                                 models.Feedback.date <= end_date).all()
    return feedbacks

# Update a feedback
@app.put("/feedbacks/{feedback_id}", response_model=schemas.FeedbackOut)
def update_feedback(feedback_id: int, feedback: schemas.FeedbackUpdate, db: Session = Depends(get_db)):
    db_feedback = db.query(models.Feedback).filter(models.Feedback.feedback_id == feedback_id).first()
    if db_feedback is None:
        raise HTTPException(status_code=404, detail="Feedback not found")
    for attr, value in feedback.dict().items():
        setattr(db_feedback, attr, value)
    db.commit()
    db.refresh(db_feedback)
    return db_feedback

# Delete a feedback
@app.delete("/feedbacks/{feedback_id}")
def delete_feedback(feedback_id: int, db: Session = Depends(get_db)):
    db_feedback = db.query(models.Feedback).filter(models.Feedback.feedback_id == feedback_id).first()
    if db_feedback is None:
        raise HTTPException(status_code=404, detail="Feedback not found")
    db.delete(db_feedback)
    db.commit()
    return {"message": "Feedback deleted successfully"}

# Create a new FAQ
@app.post("/faqs/", response_model=schemas.FAQOut)
def create_faq(faq: schemas.FAQCreate, db: Session = Depends(get_db)):
    db_faq = models.FAQ(**faq.dict())
    db.add(db_faq)
    db.commit()
    db.refresh(db_faq)
    return db_faq

# Read a single FAQ by ID
@app.get("/faqs/{faq_id}", response_model=schemas.FAQOut)
def read_faq(faq_id: int, db: Session = Depends(get_db)):
    db_faq = db.query(models.FAQ).filter(models.FAQ.id == faq_id).first()
    if db_faq is None:
        raise HTTPException(status_code=404, detail="FAQ not found")
    return db_faq

# Read all FAQs
@app.get("/faqs/", response_model=list[schemas.FAQOut])
def read_all_faqs(db: Session = Depends(get_db)):
    faqs = db.query(models.FAQ).all()
    return faqs

# Update an existing FAQ by ID
@app.put("/faqs/{faq_id}", response_model=schemas.FAQOut)
def update_faq(faq_id: int, faq: schemas.FAQUpdate, db: Session = Depends(get_db)):
    db_faq = db.query(models.FAQ).filter(models.FAQ.id == faq_id).first()
    if db_faq is None:
        raise HTTPException(status_code=404, detail="FAQ not found")
    for attr, value in faq.dict().items():
        setattr(db_faq, attr, value)
    db.commit()
    db.refresh(db_faq)
    return db_faq

# Delete an existing FAQ by ID
@app.delete("/faqs/{faq_id}")
def delete_faq(faq_id: int, db: Session = Depends(get_db)):
    db_faq = db.query(models.FAQ).filter(models.FAQ.id == faq_id).first()
    if db_faq is None:
        raise HTTPException(status_code=404, detail="FAQ not found")
    db.delete(db_faq)
    db.commit()
    return {"message": "FAQ deleted successfully"}

def api_key(length: int = 32) -> str:
    """Generate a random API key."""
    alphabet = string.ascii_letters + string.digits
    api_key = ''.join(secrets.choice(alphabet) for _ in range(length))
    return api_key

# Function to generate a new API key for a user
def generate_api_key(user_id: int, db: Session):
    new_api_key = api_key()  # Generate a new API key here
    expiration_date = datetime.utcnow() + timedelta(days=30)
    db_api_key = models.ApiKey(user_id=user_id, key=new_api_key, expiration_date=expiration_date)
    db.add(db_api_key)
    db.commit()
    db.refresh(db_api_key)
    return new_api_key

# Function to validate the API key
def authenticate_api_key(api_key: str = Header(...), db: Session = Depends(get_db)):
    db_api_key = db.query(models.ApiKey).filter(models.ApiKey.key == api_key, models.ApiKey.is_active == True).first()
    if db_api_key:
        if db_api_key.expiration_date > datetime.utcnow():
            return db_api_key.user_id
        else:
            raise HTTPException(status_code=401, detail="API Key has expired")
    else:
        raise HTTPException(status_code=401, detail="Invalid API Key")


