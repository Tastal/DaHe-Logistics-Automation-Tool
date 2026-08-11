# ADR-029: Chengfeng List Contract Rollover

## Context

The Chengfeng pending-settlement page changed the field set of its official
reset list request after the first Loop 9 read contract was frozen. The
existing firewall correctly rejected the request before network access.
Capturing production values or weakening field checks would expose business
filters and make the read scope ambiguous.

A structurally valid empty response also does not prove the detail and image
parts of the inherited contract. A temporary empty list may occur, while two
consecutive empty reads leave no real item with which to validate the
remaining operations.

## Decision

The browser Worker may emit a development-only structure diagnostic only when
the locally blocked official reset request differs from the selected list
contract. The diagnostic contains the fixed origin, path, method, query-key
name, and request field paths and types. It contains no request values,
response values, headers, credentials, or write authorization.

A rollover candidate may replace only the list request field and type
declaration. It must bind the exact selected parent contract canonical hash,
contract file hash, and freeze-evidence hash. The parent list response
contract and the parent detail and image declarations are inherited
unchanged. The rollover source and freeze evidence both state that live
validation is required.

Replacing the active candidate is atomic and is permitted only when the new
freeze evidence names the exact currently selected parent. Repeating the same
rollover is idempotent. A different parent, changed response contract, unsafe
diagnostic, symbolic link, path mismatch, or content-hash mismatch fails
closed.

During live validation, an initial empty list is read once more using the same
authorization, contract, page, and page size. A second nonempty result may
continue to bounded detail and image validation. Two consecutive empty
results stop with `pending_list_empty_confirmed`; they do not widen the date
range, change filters, select another business state, or pass the contract
gate.

## Consequences

DaHe can follow harmless official request-field evolution without retaining
production values or silently broadening read access. The inherited response,
detail, and image contracts remain unproven until a fresh live validation
reads at least one real item and exactly two ticket images with zero writes,
forbidden requests, and redirects.

When the current pending-settlement list is genuinely empty, Loop 9 waits for
eligible real data. This is an external-data gate, not a software error and
cannot be converted into acceptance evidence.
