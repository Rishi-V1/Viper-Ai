from pathlib import Path

from fastapi import APIRouter, File, HTTPException, UploadFile

from app import config
from app.services.ingestion import ingest_demo_data, ingest_uploaded_file

router = APIRouter()

SAMPLES_DIR = Path(config.BASE_DIR) / "data" / "samples"
ALLOWED_UPLOAD_EXTENSIONS = {".json", ".log", ".txt"}


@router.post("/api/ingest/sample")
def ingest_sample():
    return ingest_demo_data(SAMPLES_DIR)


@router.post("/api/ingest/upload")
async def ingest_upload(file: UploadFile = File(...)):
    suffix = Path(file.filename or "").suffix.lower()
    if suffix not in ALLOWED_UPLOAD_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported file type '{suffix}'. Allowed: {sorted(ALLOWED_UPLOAD_EXTENSIONS)}",
        )

    max_bytes = config.MAX_UPLOAD_SIZE_MB * 1024 * 1024
    raw = await file.read(max_bytes + 1)
    if len(raw) > max_bytes:
        raise HTTPException(status_code=400, detail=f"File exceeds {config.MAX_UPLOAD_SIZE_MB} MB limit")

    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise HTTPException(status_code=400, detail="File must be UTF-8 text")

    return ingest_uploaded_file(file.filename, text)
