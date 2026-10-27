from enum import Enum
from typing import Optional, List
from pydantic import BaseModel, Field

class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"
    UNKNOWN = "UNKNOWN"

class TaintProof(BaseModel):
    verified: bool
    evidence: List[str]
    taint_source: Optional[str] = None

class ImmuneResponse(BaseModel):
    invariant_holds: bool
    evidence: List[str]
    resilience_delta: float

class ValidationStatus(str, Enum):
    PENDING = "PENDING"
    CONFIRMED = "CONFIRMED"
    REJECTED = "REJECTED"
    SUSPICIOUS = "SUSPICIOUS"
    LOW_RISK = "LOW_RISK"

class RawFinding(BaseModel):
    """
    Represents a finding directly returned by the Rust Core.
    No interpretation, just facts.
    """
    id: str = Field(..., description="Unique identifier of the rule triggered in Core")
    message: str = Field(..., description="Raw description from Core")
    severity: Severity = Field(..., description="Initial severity assigned by Core")
    file_path: str = Field(..., description="Absolute path to the file")
    line: int = Field(..., description="Line number where finding occurred")
    column: int = Field(0, description="Column number (optional)")
    snippet: Optional[str] = Field(None, description="Code snippet if available")
    flow_path: List[str] = Field(default_factory=list, description="G-ASR: Structural execution path leading to the finding")
    proof: Optional[TaintProof] = Field(None, description="Deterministic taint proof from Core")
    proof_anchor: Optional[str] = Field(None, description="Robust identity anchor (context/hash) for Rust-AI matching")
    immune_context: Optional[ImmuneResponse] = Field(None, description="RBAT: Immune system response metadata")

class ValidatedFinding(BaseModel):
    """
    Represents a finding that has been processed by the Reasoning Engine.
    Includes AI context and validation status.
    """
    id: Optional[int] = Field(None, description="Database ID for referencing this finding (e.g. for fixing)")
    raw: RawFinding
    validation_status: ValidationStatus = Field(ValidationStatus.PENDING, description="AI verdict")
    ai_confidence: float = Field(0.0, ge=0.0, le=1.0, description="Confidence score of the AI (0-1)")
    reasoning_notes: str = Field("", description="Explanation of the validation decision")
    remediation_suggestion: Optional[str] = Field(None, description="AI suggested fix")
    fix_description: Optional[str] = Field(None, description="Description of the auto-fix")
    fix_code: Optional[str] = Field(None, description="Code for the auto-fix")

    # -- Provenance & preuve formelle (SOL-004), exposés en champs structurés --
    # Mêmes informations que le rapport HTML, pour qu'un client de l'API n'ait
    # pas à re-parser `reasoning_notes` (texte libre).
    proof_anchor: Optional[str] = Field(None, description="Preuve Z3 brute / ancre de robustesse")
    provenance: Optional[str] = Field(None, description="Origine de la détection : nemotron | regex_fallback")
    nemotron_line: Optional[int] = Field(None, description="Ligne rapportée par Nemotron (non fiable, pour comparaison)")
    resolved_line: Optional[int] = Field(None, description="Ligne réellement ancrée dans le source (None si ancrage échoué)")
    anchor_status: Optional[str] = Field(None, description="ANCRAGE_OK | ANCRAGE_ECHOUE")
    z3_verdict: Optional[str] = Field(None, description="Verdict Z3 : SAT | UNSAT | UNPARSED | UNKNOWN")

# The final "Finding" exposed to API could be just ValidatedFinding or a flattened version.
# For modularity, we expose ValidatedFinding as the main result.
Finding = ValidatedFinding
