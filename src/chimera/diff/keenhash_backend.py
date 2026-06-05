"""KEENHash whole-binary embedding adapter.

KEENHash (Liu et al., ISSTA 2025, https://github.com/Rroscha/KEENHash) is a
whole-binary similarity scheme: each function gets a transformer embedding,
the per-function vectors are clustered with K-Means, and the cluster
assignments are folded into a fixed-length feature-hashed signature for the
binary as a whole. Two binaries are compared by cosine similarity over
their signatures.

Why a thin adapter? The reference implementation pulls in torch +
transformers (~hundreds of MB) and a pretrained checkpoint. chimera's
default install must stay lean, so we expose KEENHash as a *backend
registration* — the heavyweight library only matters when the user has
either installed the optional `keenhash` Python package or pointed
`CHIMERA_KEENHASH_EMBEDDING_BIN` at an external command-line embedder.

Without either, `is_available()` returns False and chimera's caller falls
back to Jaccard cleanly — never an import error at module load.

The adapter exposes whole-binary embedding (not per-function), so the
`SimilarityBackend` protocol's `fingerprint(func)` falls back to a
mnemonic-shingle so per-function diff still works under the KEENHash
backend label. The novel API is `compute_embedding(model)` and
`similarity(model_a, model_b)`.
"""

from __future__ import annotations

import hashlib
import math
import os
import shutil
import subprocess
from typing import Optional

from chimera.diff.function_similarity import (
    _fingerprint,
    _jaccard,
    register_similarity_backend,
)


KEENHASH_DIM = 256  # fixed-length signature width


def _is_library_present() -> bool:
    """Probe for the optional `keenhash` Python package."""
    try:
        import importlib

        return importlib.util.find_spec("keenhash") is not None
    except Exception:
        return False


def _external_embedder_path() -> Optional[str]:
    """Look up an external embedder binary from env, if configured."""
    p = os.environ.get("CHIMERA_KEENHASH_EMBEDDING_BIN")
    if not p:
        return None
    # Either an absolute path or a name resolvable on PATH.
    if os.path.isfile(p) and os.access(p, os.X_OK):
        return p
    resolved = shutil.which(p)
    return resolved


class KEENHashBackend:
    """KEENHash similarity backend (whole-binary signature + cosine).

    Two ways to compute embeddings:
      1. `keenhash` Python package, if importable.
      2. Subprocess fallback: `CHIMERA_KEENHASH_EMBEDDING_BIN` is invoked
         with the binary path on stdin or as an argument; expects
         whitespace-separated floats on stdout.

    When neither is available `is_available()` is False — the caller must
    not invoke `compute_embedding`. The per-function `SimilarityBackend`
    protocol methods still work (degraded to Jaccard-over-mnemonics) so
    `--backend keenhash` doesn't crash a diff; it just doesn't deliver the
    whole-binary signal.
    """

    name = "keenhash"

    def __init__(self, dim: int = KEENHASH_DIM):
        self.dim = dim

    # ------------------------------------------------------------------
    # availability + whole-binary embedding
    # ------------------------------------------------------------------

    def is_available(self) -> bool:
        return _is_library_present() or _external_embedder_path() is not None

    def compute_embedding(self, model) -> list[float]:
        """Return a fixed-length numeric vector for `model`.

        Three resolution strategies, in order:
          1. The `keenhash` Python package (if installed).
          2. The configured external embedder, via subprocess.
          3. Deterministic stub: feature-hash the function mnemonic-shingles
             so callers can still test the wiring without the heavy deps.

        The stub path is what we ship for offline-only deployments. It is
        emphatically NOT the KEENHash algorithm; it's a deterministic
        feature-hashing surrogate that lets the backend be plugged into
        the rest of chimera (CLI, tests, similarity API) without forcing
        the heavyweight dependency.
        """
        lib_emb = self._try_library_embedding(model)
        if lib_emb is not None:
            return lib_emb
        ext_emb = self._try_external_embedding(model)
        if ext_emb is not None:
            return ext_emb
        return self._stub_embedding(model)

    def similarity(self, a, b) -> float:
        """Cosine similarity in [0, 1] between two precomputed signatures
        OR between two raw fingerprint sets (per-function compat path)."""
        # Per-function compat: both args are sets → defer to Jaccard.
        if isinstance(a, set) and isinstance(b, set):
            return _jaccard(a, b)
        # Whole-binary path: both args are list/tuple of floats.
        if not a or not b:
            return 0.0
        n = min(len(a), len(b))
        dot = 0.0
        na = 0.0
        nb = 0.0
        for i in range(n):
            x, y = float(a[i]), float(b[i])
            dot += x * y
            na += x * x
            nb += y * y
        if na <= 0.0 or nb <= 0.0:
            return 0.0
        cos = dot / (math.sqrt(na) * math.sqrt(nb))
        # Clamp into [0, 1] — vectors can be negative but the analyst-facing
        # contract is a non-negative score.
        return max(0.0, min(1.0, (cos + 1.0) / 2.0)) if cos < 0 else min(1.0, cos)

    # ------------------------------------------------------------------
    # per-function SimilarityBackend protocol (degraded mode)
    # ------------------------------------------------------------------

    def fingerprint(self, func) -> tuple[object, str]:
        """Fall back to the mnemonic-shingle fingerprint used by Jaccard.

        KEENHash's actual signal is per-*binary*, not per-*function*; we
        expose the mnemonic path here so the existing per-function diff
        pipeline keeps working when `--backend keenhash` is selected.
        """
        sh, src = _fingerprint(func)
        return sh, src

    # ------------------------------------------------------------------
    # private helpers — embedding sources
    # ------------------------------------------------------------------

    def _try_library_embedding(self, model) -> Optional[list[float]]:
        if not _is_library_present():
            return None
        try:
            import keenhash  # type: ignore[import-not-found]

            # The reference API exposes `embed_program(model)` returning a
            # numpy array. We accept whatever shape it produces, but coerce
            # to a Python list of floats with our target dimensionality.
            vec = keenhash.embed_program(model)  # type: ignore[attr-defined]
            return _to_fixed_dim_floats(vec, self.dim)
        except Exception:
            # Library present but broken / incompatible — don't crash the
            # diff, drop to the next strategy.
            return None

    def _try_external_embedding(self, model) -> Optional[list[float]]:
        path = _external_embedder_path()
        if not path:
            return None
        binary_path = _binary_path_from_model(model)
        if not binary_path:
            return None
        try:
            res = subprocess.run(
                [path, binary_path],
                capture_output=True,
                text=True,
                timeout=120,
            )
            if res.returncode != 0:
                return None
            tokens = res.stdout.split()
            floats = []
            for t in tokens:
                try:
                    floats.append(float(t))
                except ValueError:
                    continue
            if not floats:
                return None
            return _to_fixed_dim_floats(floats, self.dim)
        except Exception:
            return None

    def _stub_embedding(self, model) -> list[float]:
        """Deterministic feature-hashing surrogate used when no heavy deps
        are present. NOT the real KEENHash — see class docstring."""
        vec = [0.0] * self.dim
        functions = getattr(model, "functions", []) or []
        for f in functions:
            sh, _src = _fingerprint(f)
            for shingle in sh:
                # SHA-256 → two independent bucket+sign hashes (the standard
                # feature-hashing trick from Weinberger et al. 2009).
                h = hashlib.sha256(shingle.encode("utf-8")).digest()
                bucket = int.from_bytes(h[:4], "big") % self.dim
                sign = 1.0 if (h[4] & 1) else -1.0
                vec[bucket] += sign
        # L2 normalise so cosine == dot product later.
        norm = math.sqrt(sum(v * v for v in vec))
        if norm > 0.0:
            vec = [v / norm for v in vec]
        return vec


# ----------------------------------------------------------------------
# helpers
# ----------------------------------------------------------------------


def _to_fixed_dim_floats(vec, dim: int) -> list[float]:
    """Coerce an arbitrary-length numeric vector to a fixed length.

    Truncates if too long, zero-pads if too short. Used to normalise the
    library or subprocess output to our stable signature width.
    """
    out: list[float] = []
    try:
        seq = list(vec)
    except TypeError:
        seq = []
    for v in seq[:dim]:
        try:
            out.append(float(v))
        except (TypeError, ValueError):
            out.append(0.0)
    while len(out) < dim:
        out.append(0.0)
    return out


def _binary_path_from_model(model) -> Optional[str]:
    """Pull the on-disk binary path off a UnifiedProgramModel-shaped object.

    Returns None when the model isn't backed by a file we can re-read; in
    that case the subprocess embedder isn't usable.
    """
    bi = getattr(model, "binary", None)
    if bi is None:
        return None
    p = getattr(bi, "path", None)
    if not p:
        return None
    p = str(p)
    return p if os.path.isfile(p) else None


# ----------------------------------------------------------------------
# Registration
# ----------------------------------------------------------------------
#
# We register the backend instance unconditionally — looking it up via the
# pluggable hook is then always safe. Callers should consult
# `is_available()` before relying on the whole-binary embedding path; the
# per-function path always works (mnemonic-shingle Jaccard).

_INSTANCE = KEENHashBackend()
register_similarity_backend("keenhash", _INSTANCE)


def get_keenhash_backend() -> KEENHashBackend:
    """Return the module-level singleton (mostly for tests)."""
    return _INSTANCE
