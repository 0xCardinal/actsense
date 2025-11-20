"""Storage for analysis results."""
import json
import os
import datetime
from typing import Dict, Any, List, Optional
from pathlib import Path
import uuid


class AnalysisStorage:
    """Store and retrieve analysis results."""
    
    def __init__(self, storage_dir: Optional[str] = None):
        """Initialize storage directory."""
        if storage_dir:
            self.storage_dir = Path(storage_dir)
        else:
            self.storage_dir = Path(__file__).parent.parent / "data" / "analyses"
        
        self.storage_dir.mkdir(parents=True, exist_ok=True)
    
    def save_analysis(
        self,
        repository: Optional[str],
        action: Optional[str],
        graph_data: Dict[str, Any],
        statistics: Dict[str, Any],
        method: str = "api"
    ) -> str:
        """Save an analysis and return its ID."""
        analysis_id = str(uuid.uuid4())
        
        analysis = {
            "id": analysis_id,
            "timestamp": datetime.datetime.now(datetime.UTC).isoformat(),
            "repository": repository,
            "action": action,
            "method": method,
            "graph": graph_data,
            "statistics": statistics
        }
        
        file_path = self.storage_dir / f"{analysis_id}.json"
        with open(file_path, 'w') as f:
            json.dump(analysis, f, indent=2)
        
        return analysis_id
    
    def get_analysis(self, analysis_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve an analysis by ID."""
        file_path = self.storage_dir / f"{analysis_id}.json"
        if not file_path.exists():
            return None
        
        with open(file_path, 'r') as f:
            return json.load(f)
    
    def list_analyses(
        self,
        limit: int = 50,
        repository: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """List all analyses, optionally filtered by repository."""
        analyses = []
        
        for file_path in sorted(
            self.storage_dir.glob("*.json"),
            key=lambda p: p.stat().st_mtime,
            reverse=True
        ):
            try:
                with open(file_path, 'r') as f:
                    analysis = json.load(f)
                    
                # Filter by repository if specified
                if repository and analysis.get("repository") != repository:
                    continue
                
                # Return only metadata, not full graph data
                analyses.append({
                    "id": analysis["id"],
                    "timestamp": analysis["timestamp"],
                    "repository": analysis.get("repository"),
                    "action": analysis.get("action"),
                    "method": analysis.get("method", "api"),
                    "statistics": analysis.get("statistics", {})
                })
                
                if len(analyses) >= limit:
                    break
            except Exception as e:
                print(f"Error reading analysis {file_path}: {e}")
                continue
        
        return analyses
    
    def delete_analysis(self, analysis_id: str) -> bool:
        """Delete an analysis by ID."""
        file_path = self.storage_dir / f"{analysis_id}.json"
        if file_path.exists():
            file_path.unlink()
            return True
        return False

