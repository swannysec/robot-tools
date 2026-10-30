# Deterministic repository quotations

Before discovery, the caller independently resolves immutable repository snapshots, captures the initial snapshot intake and file hashes once, builds the source registry, and independently retains its SHA-256 digest in frozen caller dispatch and provenance outside role control. The preparer rejects any changes detected while freezing. The registry is trusted run input, never model or role output. Its shape is:

```json
{"sources":[{"repository":"repo","revision":"immutable-revision","root":"ABSOLUTE_SNAPSHOT_ROOT","files":[{"relative_path":"src/file.rs","sha256":"file-sha256","allowed_ranges":[[1,20]]}]}]}
```

Register only declared repositories, pinned revisions, canonical relative paths, file hashes, and permitted positive full-line ranges. The root identifies the corresponding pinned snapshot; independently establish that correspondence before discovery. Freeze this registry and its independently retained expected digest before dispatch; do not expand it in response to role output. The runtime root must be absolute. Never derive the expected digest from a mutable companion manifest at acceptance.

Use full lowercase 40- or 64-hex revisions and 64-hex SHA-256 file digests in the registry. The example values above are placeholders.

The citation schema still requires `quote` to be a string. In every discovery, native verification, cross-provider verification, and fix artifact, roles select the repository, revision, canonical path, and positive inclusive full-line range and emit `quote: ""`. Any supplied raw quote text is untrusted and retained only in the raw output. Runtime and deterministic-check output citations and authoritative-source citations remain unchanged and still require their existing artifact registry and evidence validation.

After receiving each raw role artifact, run the packaged extractor before completion or cardinality checks and before constructing packets or reports:

```sh
python3 scripts/source-citations.py --artifact RAW --sources REGISTRY --expected-sources-sha256 DIGEST --output NEW_ENVELOPE
```

The output must be a new path; the script refuses to overwrite an existing file. It derives an envelope containing `artifact`, the role object with only repository citation `quote` fields replaced by exact pinned UTF-8 source text, and `provenance`, containing `raw_artifact_sha256`, `source_registry_sha256`, `derived_artifact_sha256`, and `citations`. Preserve the raw bytes, registry, envelope, and all attempt history. Preserve full line endings exactly, with no stripping or newline normalization.

Pass the independently retained expected digest to the extractor and verify the binding of raw artifact, frozen registry, derived artifact, and citation provenance against it before accepting the derived artifact. Apply the applicable schema and literal role-local ID checks as well as ordinary citation validation before downstream use. A wrong repository or revision, file hash mismatch, malformed or out-of-range reference, invalid UTF-8, or symlink escape makes the attempt `MALFORMED`; the ordinary identical-packet retry applies, and an unrepaired mandatory result is `INCOMPLETE`. Do not copy a quote by hand.

The raw and registry hashes cover their exact input bytes. The derived hash covers UTF-8 JSON serialized with sorted keys, `ensure_ascii=False`, compact separators `(',', ':')`, and no non-JSON numbers. Each citation receipt records its JSON pointer, unchanged repository/revision/path/range, frozen file digest, and SHA-256 of the exact extracted UTF-8 quotation. Validate the raw role schema and literal ID boundary before extraction, then validate the derived role schema and verdict-dependent cardinality before acceptance. Non-repository citations require separate existing evidence validation; this extractor does not authenticate them.

Extraction is mechanical: it does not choose or repair locations or observations, alter judgments, determine validity, repair malformed references, expand scope, or retry failed historical roles. Historical failed evaluations remain failed and are not retroactively reclassified. The orchestrator may invoke this extraction but must not exercise security judgment.
