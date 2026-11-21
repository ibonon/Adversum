from enum import Enum
from typing import Optional, List
from pydantic import BaseModel, Field, model_validator

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

class ProofVerdict(str, Enum):
    """Proof verdicts (Steps 1+3 — never mix these badges).

    PROVEN requires an attached witness (counterexample + reachable
    entry, or an executed trace). DETECTED_UNPROVEN is a high-confidence
    heuristic/rule detection. UNKNOWN means the verifier could not
    decide (UNPARSED, timeout, failed anchoring) — never "safe".

    DEPENDENCY_PROVEN (Step 3, 4th state — justified because the
    3-state schema cannot express it): a source->sink dependency path
    is demonstrated (entropy/oracle/loop-bound taint) but exploitability
    is NOT proven. Stronger than DETECTED_UNPROVEN (a path is shown),
    weaker than PROVEN (no exploit witness). UI label:
    "DEPENDENCY PROVEN - EXPLOIT UNPROVEN".
    """
    PROVEN = "PROVEN"
    DEPENDENCY_PROVEN = "DEPENDENCY_PROVEN"
    DETECTED_UNPROVEN = "DETECTED_UNPROVEN"
    UNKNOWN = "UNKNOWN"

class Witness(BaseModel):
    """Verifiable evidence attached to a PROVEN verdict."""
    kind: str = Field(..., description="z3_counterexample | halmos_counterexample | foundry_execution | execution_trace | dependency_path")
    solver: Optional[str] = Field(None, description="Tool that produced the witness (z3, halmos, hevm, foundry)")
    entry_point: Optional[str] = Field(None, description="External entry function reaching the sink")
    call_path: List[str] = Field(default_factory=list, description="Entry -> ... -> sink call path")
    counterexample: dict = Field(default_factory=dict, description="Concrete solver/model values")
    scope: str = Field("", description="Exact scope of the proof (what it does and does not cover)")
    artifact: Optional[str] = Field(None, description="Replayable artifact (PoC path, trace hash, forge output)")

def classify_proof_verdict(
    *,
    z3_verdict: Optional[str] = None,
    reachable: Optional[bool] = None,
    witness: Optional[Witness] = None,
    anchor_status: Optional[str] = None,
    validation_status: Optional[str] = None,
) -> ProofVerdict:
    """Single classification rule for the whole chain (Step 1).

    PROVEN only with a witness *and* a positive solver verdict on a
    reachable path. Representability alone (SAT, not reachable) is
    DETECTED_UNPROVEN. UNPARSED/UNKNOWN/failed anchoring is UNKNOWN.
    """
    if anchor_status == "ANCRAGE_ECHOUE":
        return ProofVerdict.UNKNOWN
    if z3_verdict in ("UNPARSED", "UNKNOWN", "ERROR"):
        return ProofVerdict.UNKNOWN
    if str(validation_status or "").upper() == "REJECTED":
        return ProofVerdict.UNKNOWN
    if witness is not None and z3_verdict == "SAT" and reachable:
        return ProofVerdict.PROVEN
    # Step 2: a Halmos/Foundry witness carries its own solver verdict —
    # the concrete counterexample *is* the entry->sink proof for the
    # harness target. An empty witness never proves anything.
    if witness is not None and witness.kind in ("halmos_counterexample", "foundry_execution", "execution_trace"):
        if witness.counterexample or witness.call_path:
            return ProofVerdict.PROVEN
    # Step 3: a demonstrated source->sink dependency path (with the
    # source and sink named in the witness) proves dependency only.
    if witness is not None and witness.kind == "dependency_path":
        if witness.call_path and witness.counterexample.get("source") and witness.counterexample.get("sink"):
            return ProofVerdict.DEPENDENCY_PROVEN
    return ProofVerdict.DETECTED_UNPROVEN

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
    is_fixed: bool = Field(False, description="Un correctif vérifié a été appliqué (AVR)")

    # -- Verdict de preuve à trois états (Étape 1) --
    proof_verdict: ProofVerdict = Field(ProofVerdict.DETECTED_UNPROVEN, description="PROVEN | DETECTED_UNPROVEN | UNKNOWN")
    witness: Optional[Witness] = Field(None, description="Témoin vérifiable — obligatoire si proof_verdict=PROVEN")
    verdict_reason: str = Field("", description="Pourquoi ce verdict (portée exacte, jamais marketing)")

    @model_validator(mode="after")
    def _proven_requires_witness(self):
        """PROVEN / DEPENDENCY_PROVEN without their witness are impossible."""
        if self.proof_verdict == ProofVerdict.PROVEN and self.witness is None:
            self.proof_verdict = ProofVerdict.DETECTED_UNPROVEN
            self.verdict_reason = (
                (self.verdict_reason + " " if self.verdict_reason else "")
                + "[downgraded: PROVEN claimed without witness]"
            ).strip()
        if self.proof_verdict == ProofVerdict.DEPENDENCY_PROVEN and (
            self.witness is None or self.witness.kind != "dependency_path"
        ):
            self.proof_verdict = ProofVerdict.DETECTED_UNPROVEN
            self.verdict_reason = (
                (self.verdict_reason + " " if self.verdict_reason else "")
                + "[downgraded: DEPENDENCY_PROVEN claimed without dependency witness]"
            ).strip()
        return self

# The final "Finding" exposed to API could be just ValidatedFinding or a flattened version.
# For modularity, we expose ValidatedFinding as the main result.
Finding = ValidatedFinding
