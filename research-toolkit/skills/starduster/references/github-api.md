# GitHub API behavior

This reference describes controller internals. The host invokes only
`starduster.py sync`; it does not run GitHub commands, parse API responses, or inspect
the controller workspace.

## Read-only authority

The controller requires an authenticated `gh` CLI and uses only read-only GitHub API
operations: authentication status, rate-limit inspection, the authenticated user's
starred-repositories collection, and batched GraphQL repository metadata/README reads.
`jq` is not a runtime dependency. Missing `gh`, failed authentication, or an unsuitable
read-only response produces a safe controller error before star fetching or synthesis.

## Star-list shape

The starred-repositories response uses GitHub's `application/vnd.github.star+json`
representation. Every item has a `starred_at` timestamp and a nested `repo` object.
The controller normalizes the complete paginated list before diffing it with existing
catalog identities. The `--limit` value affects only newly synthesized notes, never the
identity inventory.

The validated repository metadata used by later controller stages includes `full_name`,
owner login, URL, language, normalized topics, license identifier, stars, forks,
archived/fork state, parent identity where present, creation/push timestamps, and
`starred_at`. Repository descriptions and README text remain untrusted private inputs.

## README batches and rate estimates

The controller batches up to 100 repositories per GraphQL request and considers
`README.md`, `readme.md`, `README.rst`, then `README` in that order. It records only
bounded availability and byte-size metadata outside the raw response boundary. A README
over the controller's byte limit is marked oversized rather than passed unbounded to
synthesis.

The preflight estimate accounts for star-list pages and README batches. It warns above
10% of the remaining budget and returns safe `confirmation_required` details above 25%.
The host may rerun only with explicit `--confirm-rate`; noninteractive use never assumes
approval.

## Input integrity

Before constructing a GraphQL batch, the controller accepts repository identities only
when they match the GitHub owner/repository form. Invalid entries are skipped and counted
safely. GraphQL failures, unavailable repositories, and exhausted rate budgets are
reported as bounded warnings or safe failures without exposing response bodies.
