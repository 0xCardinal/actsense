"""Storage for analysis results."""
import json
import logging
import os
import datetime
import threading
from typing import Dict, Any, List, Optional
from pathlib import Path
import uuid

logger = logging.getLogger(__name__)


class AnalysisStorage:
    """Store and retrieve analysis results.

    All write operations (save, delete) are protected by an in-process lock so
    concurrent audit requests cannot corrupt each other's JSON files.
    """

    def __init__(self, storage_dir: Optional[str] = None):
        """Initialize storage directory."""
        if storage_dir:
            self.storage_dir = Path(storage_dir)
        else:
            self.storage_dir = Path(__file__).parent.parent / "data" / "analyses"

        self.storage_dir.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

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
        with self._lock:
            # Write to a temp file first, then atomically rename so a partial
            # write never leaves a corrupted JSON file on disk.
            tmp_path = file_path.with_suffix(".tmp")
            try:
                with open(tmp_path, 'w') as f:
                    json.dump(analysis, f, indent=2)
                tmp_path.replace(file_path)
            except Exception:
                tmp_path.unlink(missing_ok=True)
                raise

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
            except Exception:
                logger.exception("Error reading analysis file %s", file_path)
                continue

        return analyses

    def delete_analysis(self, analysis_id: str) -> bool:
        """Delete an analysis by ID."""
        file_path = self.storage_dir / f"{analysis_id}.json"
        with self._lock:
            if file_path.exists():
                file_path.unlink()
                return True
        return False

    # Org scans group the per-repository analyses of one organization run.
    # They live in a subdirectory so list_analyses() never picks them up.

    @property
    def org_scan_dir(self) -> Path:
        path = self.storage_dir / "org_scans"
        path.mkdir(parents=True, exist_ok=True)
        return path

    def _org_scan_path(self, scan_id: str) -> Optional[Path]:
        try:
            uuid.UUID(scan_id)
        except (ValueError, TypeError):
            return None
        return self.org_scan_dir / f"{scan_id}.json"

    def save_org_scan(self, scan: Dict[str, Any]) -> str:
        """Save an org scan summary and return its ID."""
        scan_id = str(uuid.uuid4())
        record = {"id": scan_id, "timestamp": datetime.datetime.now(datetime.UTC).isoformat(), **scan}
        file_path = self.org_scan_dir / f"{scan_id}.json"
        with self._lock:
            tmp_path = file_path.with_suffix(".tmp")
            try:
                with open(tmp_path, 'w') as f:
                    json.dump(record, f, indent=2)
                tmp_path.replace(file_path)
            except Exception:
                tmp_path.unlink(missing_ok=True)
                raise
        return scan_id

    def get_org_scan(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve an org scan by ID."""
        file_path = self._org_scan_path(scan_id)
        if file_path is None or not file_path.exists():
            return None
        with open(file_path, 'r') as f:
            return json.load(f)

    def list_org_scans(self, limit: int = 50, org: Optional[str] = None) -> List[Dict[str, Any]]:
        """List org scans (metadata only), newest first."""
        scans = []
        for file_path in sorted(self.org_scan_dir.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True):
            try:
                with open(file_path, 'r') as f:
                    scan = json.load(f)
            except Exception:
                logger.exception("Error reading org scan file %s", file_path)
                continue
            if org and str(scan.get("org", "")).lower() != org.lower():
                continue
            scans.append({
                "id": scan["id"],
                "timestamp": scan["timestamp"],
                "org": scan.get("org"),
                "statistics": scan.get("statistics", {}),
            })
            if len(scans) >= limit:
                break
        return scans

    def delete_org_scan(self, scan_id: str) -> bool:
        """Delete an org scan (its per-repository analyses are kept)."""
        file_path = self._org_scan_path(scan_id)
        with self._lock:
            if file_path is not None and file_path.exists():
                file_path.unlink()
                return True
        return False
