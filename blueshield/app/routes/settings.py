from fastapi import APIRouter

from app.services import settings_store

router = APIRouter()


@router.get("/api/settings")
def get_settings():
    return settings_store.load()


@router.post("/api/settings")
def update_settings(partial: dict):
    return settings_store.save(partial)
