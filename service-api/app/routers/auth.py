from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from datetime import datetime, timedelta
from jose import JWTError, jwt
from passlib.context import CryptContext
from typing import Optional

from .. import models, schemas
from ..database import SessionLocal
from ..logger import JSONLogger  # Import du logger personnalisé

# Configuration secrète (à mettre dans variables d'environnement)
SECRET_KEY = "une_clé_secrète_très_longue_et_aléatoire"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Utilisation d'Argon2 à la place de bcrypt
pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")

router = APIRouter(prefix="/api/auth", tags=["authentication"])

# Dépendance pour obtenir la session DB
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# ------------------- Fonctions d'authentification -------------------
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def authenticate_user(db: Session, username: str, password: str):
    user = db.query(models.User).filter(
        (models.User.username == username) | (models.User.email == username)
    ).first()
    if not user or not verify_password(password, user.hashed_password):
        return False
    return user

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# ------------------- Routes -------------------
@router.post("/register", response_model=schemas.User)
def register(
    user_data: schemas.UserCreate,
    request: Request,
    db: Session = Depends(get_db)
):
    # Log de la tentative d'inscription
    JSONLogger.log("service-api", "registration_attempt", {
        "email": user_data.email,
        "username": user_data.username,
        "ip": request.client.host,
        "user_agent": request.headers.get("user-agent")
    })

    # Vérifier si l'utilisateur existe déjà
    existing_user = db.query(models.User).filter(
        (models.User.username == user_data.username) | (models.User.email == user_data.email)
    ).first()
    if existing_user:
        JSONLogger.log("service-api", "registration_failed", {
            "reason": "user already exists",
            "email": user_data.email,
            "username": user_data.username
        })
        raise HTTPException(status_code=400, detail="Username or email already registered")

    # Créer le nouvel utilisateur
    hashed_password = get_password_hash(user_data.password)
    db_user = models.User(
        email=user_data.email,
        username=user_data.username,
        hashed_password=hashed_password
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)

    JSONLogger.log("service-api", "registration_success", {
        "user_id": db_user.id,
        "email": db_user.email,
        "username": db_user.username
    })

    return db_user

@router.post("/token", response_model=schemas.Token)
def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    request: Request = None,
    db: Session = Depends(get_db)
):
    # Log de la tentative de connexion
    JSONLogger.log("service-api", "login_attempt", {
        "username": form_data.username,
        "ip": request.client.host if request else "unknown",
        "user_agent": request.headers.get("user-agent") if request else "unknown"
    })

    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        JSONLogger.log("service-api", "login_failed", {
            "username": form_data.username,
            "reason": "invalid credentials"
        })
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token = create_access_token(data={"sub": user.username})

    JSONLogger.log("service-api", "login_success", {
        "user_id": user.id,
        "username": user.username
    })

    return {"access_token": access_token, "token_type": "bearer"}
