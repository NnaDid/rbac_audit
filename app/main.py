from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from . import models, database, routes
from .config import settings 

app = FastAPI(title=settings.PROJECT_NAME, version=settings.PROJECT_VERSION)

# Middleware: CORS = Cross Origin Resource Sharing 
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

models.Base.metadata.create_all(bind=database.engine)

app.include_router(routes.router)