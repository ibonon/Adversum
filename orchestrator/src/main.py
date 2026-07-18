from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from .schemas import ScanRequest, AnalysisResult, Finding

app = FastAPI(
    title="Adversum API",
    description="Orchestrator for Adversum Security Engine",
    version="0.1.0"
)

# CORS (Allow Frontend)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # In production, restrict this
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/health")
def health_check():
    return {"status": "ok", "component": "orchestrator"}

@app.post("/analyze", response_model=AnalysisResult)
async def analyze_project(request: ScanRequest):
    from .pipeline import AnalysisPipeline
    try:
        pipeline = AnalysisPipeline(request.project_id, request.path)
        result = pipeline.run()
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("src.main:app", host="0.0.0.0", port=8000, reload=True)
