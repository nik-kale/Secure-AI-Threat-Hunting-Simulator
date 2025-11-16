"""
FastAPI server for analysis engine.
"""
from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pathlib import Path
from typing import Any, Dict
import tempfile
import logging
import json

from analysis_engine.pipeline import ThreatHuntingPipeline

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="AI Threat Hunting Simulator API",
    description="Analysis engine API for threat hunting",
    version="1.0.0"
)

# Enable CORS for UI
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, specify allowed origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize pipeline
pipeline = ThreatHuntingPipeline()


@app.get("/")
async def root():
    """Root endpoint."""
    return {
        "service": "AI Threat Hunting Simulator API",
        "version": "1.0.0",
        "status": "operational"
    }


@app.get("/health")
async def health():
    """Health check endpoint."""
    return {"status": "healthy"}


@app.post("/analyze/upload")
async def analyze_upload(file: UploadFile = File(...)) -> Dict[str, Any]:
    """
    Analyze uploaded telemetry file.

    Args:
        file: Uploaded telemetry file (JSONL or JSON)

    Returns:
        Analysis results
    """
    try:
        # Save uploaded file to temp location
        with tempfile.NamedTemporaryFile(
            mode='wb',
            suffix=Path(file.filename).suffix,
            delete=False
        ) as tmp_file:
            content = await file.read()
            tmp_file.write(content)
            tmp_path = Path(tmp_file.name)

        # Analyze
        results = pipeline.analyze_telemetry_file(tmp_path)

        # Cleanup
        tmp_path.unlink()

        return results

    except Exception as e:
        logger.error(f"Analysis failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/analyze/data")
async def analyze_data(events: list) -> Dict[str, Any]:
    """
    Analyze telemetry events provided as JSON.

    Args:
        events: List of telemetry events

    Returns:
        Analysis results
    """
    try:
        # Write events to temp file
        with tempfile.NamedTemporaryFile(
            mode='w',
            suffix='.jsonl',
            delete=False
        ) as tmp_file:
            for event in events:
                tmp_file.write(json.dumps(event) + '\n')
            tmp_path = Path(tmp_file.name)

        # Analyze
        results = pipeline.analyze_telemetry_file(tmp_path)

        # Cleanup
        tmp_path.unlink()

        return results

    except Exception as e:
        logger.error(f"Analysis failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/scenarios")
async def list_scenarios() -> Dict[str, Any]:
    """
    List available pre-generated scenarios.

    Returns:
        List of scenario metadata
    """
    scenarios_dir = Path("output/scenarios")

    if not scenarios_dir.exists():
        return {"scenarios": []}

    scenarios = []

    for scenario_path in scenarios_dir.iterdir():
        if scenario_path.is_dir():
            metadata_file = scenario_path / "metadata.json"

            if metadata_file.exists():
                with open(metadata_file) as f:
                    metadata = json.load(f)
                    scenarios.append({
                        "name": scenario_path.name,
                        **metadata
                    })

    return {"scenarios": scenarios}


@app.get("/scenarios/{scenario_name}")
async def get_scenario(scenario_name: str) -> Dict[str, Any]:
    """
    Get analysis results for a specific scenario.

    Args:
        scenario_name: Name of the scenario

    Returns:
        Scenario analysis results
    """
    scenario_path = Path("output/scenarios") / scenario_name

    if not scenario_path.exists():
        raise HTTPException(status_code=404, detail="Scenario not found")

    # Check for existing analysis
    analysis_file = scenario_path / "analysis_report.json"

    if analysis_file.exists():
        with open(analysis_file) as f:
            return json.load(f)

    # Otherwise analyze on the fly
    telemetry_file = scenario_path / "telemetry.jsonl"

    if not telemetry_file.exists():
        raise HTTPException(
            status_code=404,
            detail="Telemetry file not found for scenario"
        )

    results = pipeline.analyze_telemetry_file(telemetry_file, scenario_path)
    return results


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
