#!/usr/bin/env bash
# Cut a containment release. Dry run by default; --execute tags, pushes, waits for the
# publish workflow, verifies its attested dists, and creates the GitHub Release.
# Runbook: docs/RELEASE.md
set -euo pipefail

REPO="Hyper-AI-Lab/prompt-injection-defense"
WORKFLOW="publish.yml"
SIGNER="$REPO/.github/workflows/$WORKFLOW"

usage() {
  cat <<'USAGE'
Usage: scripts/cut_release.sh X.Y.Z [--execute]

  X.Y.Z      version to release; must equal pyproject.toml and containment.__version__
  --execute  create + push annotated tag vX.Y.Z, wait for the publish workflow,
             verify attested dists, create the GitHub Release (default: dry run)

Exits non-zero on the first failed check. See docs/RELEASE.md.
USAGE
}

die() { echo "cut_release: FAIL: $*" >&2; exit 1; }
step() { echo "cut_release: $*"; }

VERSION=""
EXECUTE=0
for arg in "$@"; do
  case "$arg" in
    -h|--help) usage; exit 0 ;;
    --execute) EXECUTE=1 ;;
    -*) usage >&2; die "unknown option: $arg" ;;
    *) [[ -z "$VERSION" ]] || die "more than one version given"; VERSION="$arg" ;;
  esac
done
[[ -n "$VERSION" ]] || { usage >&2; die "version argument required"; }

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
TAG="v$VERSION"

# 1. Plain semver.
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "version '$VERSION' is not MAJOR.MINOR.PATCH"

# 2. Version sync.
py_version="$(sed -n 's/^version = "\(.*\)"$/\1/p' pyproject.toml | head -n1)"
init_version="$(sed -n 's/^__version__ = "\(.*\)"$/\1/p' src/containment/__init__.py | head -n1)"
[[ "$py_version" == "$VERSION" ]] || die "version mismatch: pyproject.toml=$py_version, requested=$VERSION"
[[ "$init_version" == "$VERSION" ]] || die "version mismatch: containment.__version__=$init_version, requested=$VERSION"
step "version $VERSION matches pyproject.toml and __version__"

# 3. CHANGELOG section (notes for the GitHub Release).
NOTES_DIR="$(mktemp -d)"
trap 'rm -rf "$NOTES_DIR"' EXIT
NOTES="$NOTES_DIR/notes-$TAG.md"
awk -v hdr="## [$VERSION]" '
  index($0, hdr) == 1 { on = 1; next }
  on && /^## \[/ { exit }
  on && /^\[[^]]+\]: / { exit }
  on { print }
' CHANGELOG.md > "$NOTES"
grep -q '[^[:space:]]' "$NOTES" || die "CHANGELOG.md has no non-empty '## [$VERSION]' section"
step "release notes extracted from CHANGELOG.md ($(wc -l < "$NOTES") lines)"

# 4. Tag must not exist locally.
git rev-parse --git-dir >/dev/null 2>&1 || die "not a git repository: $ROOT"
if git rev-parse -q --verify "refs/tags/$TAG" >/dev/null; then
  die "tag $TAG already exists locally"
fi

# 5. Clean tree (tracked + untracked, ignoring .gitignore'd files).
[[ -z "$(git status --porcelain)" ]] || die "working tree is dirty (commit or stash first)"
step "working tree clean"

# 6. HEAD == origin/main, tag absent on origin.
git fetch --quiet origin main || die "git fetch origin main failed"
head_sha="$(git rev-parse HEAD)"
[[ "$head_sha" == "$(git rev-parse origin/main)" ]] || die "HEAD $head_sha is not origin/main"
if [[ -n "$(git ls-remote --tags origin "refs/tags/$TAG")" ]]; then
  die "tag $TAG already exists on origin"
fi
step "HEAD ${head_sha:0:12} == origin/main; $TAG free on origin"

# 7. Release gate.
bash scripts/release_gate.sh || die "scripts/release_gate.sh failed"
# shellcheck disable=SC1091
source .venv/bin/activate

# 8. Eval card (fail-closed gate, attached to the release).
CARD_DIR="artifacts/eval-card"
containment-eval-card --suite fixtures --out-dir "$CARD_DIR" || die "eval card gate=FAIL"
step "eval card gate=PASS ($CARD_DIR)"

# 9. Local build smoke (release assets come from the attested CI build, not this one).
python -m pip install --quiet "build>=1.2"
rm -rf "$NOTES_DIR/dist"
python -m build --outdir "$NOTES_DIR/dist" >/dev/null || die "python -m build failed"
step "local build OK: $(find "$NOTES_DIR/dist" -maxdepth 1 -type f -printf '%f ')"

if [[ "$EXECUTE" -eq 0 ]]; then
  step "dry run OK. --execute would run:"
  cat <<CMDS
  git tag -a $TAG -m "containment $VERSION" $head_sha
  git push origin refs/tags/$TAG
  gh run watch <publish run for $TAG> --exit-status -R $REPO
  gh run download <run> -n dist -D <tmp>/dist -R $REPO
  gh attestation verify <tmp>/dist/<file> -R $REPO --source-ref refs/tags/$TAG --signer-workflow $SIGNER
  gh release create $TAG --verify-tag --title "containment $VERSION" --notes-file <CHANGELOG [$VERSION]> \\
    <tmp>/dist/* $CARD_DIR/eval-card.md $CARD_DIR/eval-card.json -R $REPO
CMDS
  exit 0
fi

# --execute
gh auth status >/dev/null 2>&1 || die "gh is not authenticated"
gh attestation verify --help >/dev/null 2>&1 || die "gh lacks 'attestation verify' (need gh >= 2.49)"
git tag -a "$TAG" -m "containment $VERSION" "$head_sha"
git push origin "refs/tags/$TAG" || die "push of $TAG failed"
step "pushed $TAG"

run_id=""
for _ in $(seq 1 30); do
  run_id="$(gh run list -R "$REPO" --workflow "$WORKFLOW" --event push --commit "$head_sha" \
    --json databaseId,headBranch --jq ".[] | select(.headBranch == \"$TAG\") | .databaseId" \
    | head -n1)"
  [[ -n "$run_id" ]] && break
  sleep 10
done
[[ -n "$run_id" ]] || die "no $WORKFLOW run found for $TAG after 300s (tag pushed; no release created)"
step "waiting for $WORKFLOW run $run_id"
gh run watch "$run_id" -R "$REPO" --exit-status >/dev/null \
  || die "$WORKFLOW run $run_id failed (tag pushed; no release created)"

DIST="$NOTES_DIR/release-dist"
gh run download "$run_id" -R "$REPO" -n dist -D "$DIST" || die "download of dist artifact failed"
shopt -s nullglob
assets=("$DIST"/containment-"$VERSION"-*.whl "$DIST"/containment-"$VERSION".tar.gz)
shopt -u nullglob
[[ "${#assets[@]}" -eq 2 ]] || die "expected wheel + sdist for $VERSION in dist artifact, got: ${assets[*]:-none}"
for f in "${assets[@]}"; do
  gh attestation verify "$f" -R "$REPO" --source-ref "refs/tags/$TAG" --signer-workflow "$SIGNER" \
    >/dev/null || die "attestation verify failed: $(basename "$f")"
  step "attestation verified: $(basename "$f")"
done

gh release create "$TAG" -R "$REPO" --verify-tag --title "containment $VERSION" \
  --notes-file "$NOTES" "${assets[@]}" "$CARD_DIR/eval-card.md" "$CARD_DIR/eval-card.json" \
  || die "gh release create failed"
step "released $TAG: https://github.com/$REPO/releases/tag/$TAG"
