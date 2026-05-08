from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from .database import engine, Base
from .routers import auth as auth_router, users as users_router
from fastapi.middleware.cors import CORSMiddleware

# Créer les tables dans la base de données
Base.metadata.create_all(bind=engine)

app = FastAPI(title="Service A - User API")

# Configuration des templates et fichiers statiques
templates = Jinja2Templates(directory="templates")
app.mount("/static", StaticFiles(directory="static"), name="static")

# Routers API
app.include_router(auth_router.router)
app.include_router(users_router.router)

@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    """Page d'accueil avec interface de test"""
    return templates.TemplateResponse("home.html", {"request": request})

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

@app.get("/register", response_class=HTMLResponse)
async def register_page(request: Request):
    return templates.TemplateResponse("register.html", {"request": request})

@app.get("/profile", response_class=HTMLResponse)
async def profile_page(request: Request):
    return templates.TemplateResponse("profile.html", {"request": request})

@app.get("/health")
async def health():
    return {"status": "healthy"}
