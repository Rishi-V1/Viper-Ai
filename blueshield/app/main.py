from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from app.database.db import init_db
from app.routes import analyze, evaluation, events, health, incidents, ingest, settings as settings_routes, stats

BASE_DIR = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(title="BlueShield", lifespan=lifespan)
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")
app.include_router(health.router)
app.include_router(ingest.router)
app.include_router(events.router)
app.include_router(incidents.router)
app.include_router(settings_routes.router)
app.include_router(stats.router)
app.include_router(analyze.router)
app.include_router(evaluation.router)


@app.get("/", response_class=HTMLResponse)
def overview_page(request: Request):
    return templates.TemplateResponse("overview.html", {"request": request})


@app.get("/incidents", response_class=HTMLResponse)
def incidents_page(request: Request):
    return templates.TemplateResponse("incidents.html", {"request": request})


@app.get("/incidents/{incident_id}", response_class=HTMLResponse)
def incident_detail_page(request: Request, incident_id: str):
    return templates.TemplateResponse("incident_detail.html", {"request": request, "incident_id": incident_id})


@app.get("/events", response_class=HTMLResponse)
def events_page(request: Request):
    return templates.TemplateResponse("events.html", {"request": request})


@app.get("/ingest", response_class=HTMLResponse)
def ingest_page(request: Request):
    return templates.TemplateResponse("ingest.html", {"request": request})


@app.get("/evaluation", response_class=HTMLResponse)
def evaluation_page(request: Request):
    return templates.TemplateResponse("evaluation.html", {"request": request})


@app.get("/reports", response_class=HTMLResponse)
def reports_page(request: Request):
    return templates.TemplateResponse("reports.html", {"request": request})


@app.get("/settings", response_class=HTMLResponse)
def settings_page(request: Request):
    return templates.TemplateResponse("settings.html", {"request": request})
