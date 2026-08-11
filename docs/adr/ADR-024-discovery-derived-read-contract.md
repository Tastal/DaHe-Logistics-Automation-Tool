# ADR-024: Discovery-Derived Chengfeng Read Contract

## Context

The first authorized development discovery captured 51 sanitized request
shapes while a person viewed the pending-settlement list, one detail, and both
ticket images. The evidence retained no credential material, header values,
request values, response values, raw responses, or signed image paths.

Only two JSON operations were necessary for the product: the pending-settlement
waybill list and one waybill detail. Three signed image reads came from two
object-storage origins. The Chengfeng page also initiated many unrelated
background requests. Five excluded paths matched conservative mutation markers
such as `update` or `switch`. Their names do not prove a business write, but
they mean that a manually opened platform page cannot be used as evidence of
zero write-shaped traffic.

## Decision

Freeze the executable read contract from the sealed discovery evidence, not
from browser history, logs, or the legacy runtime. The contract accepts exactly:

- one POST JSON pending-settlement list path;
- one POST JSON waybill-detail path;
- response-derived ticket images authorized by a short-lived capability for
  one exact complete URL hash and one approved image origin.

The list request builder constructs the current pending-settlement scope from
code-owned safe defaults. It permits only bounded page numbers and at most 100
rows per page, keeps all unused filters empty, fixes descending order, and
keeps the native settlement query mode fixed. The detail request accepts only
an ASCII numeric platform item identity. The firewall rejects extra keys,
populated filter arrays, changed methods, origins, paths, types, redirects, and
direct image URLs.

The real contract and its deterministic freeze evidence live under the new
application's AppData. The repository retains only a non-routable `.invalid`
fixture. The contract records the source discovery hash, observation count,
required response fields, and approved image origins without recording any
platform value.

Do not use normal Chengfeng page navigation for formal locked-set or shadow
collection. Those runs must use the isolated connector and frozen request
contract. The development discovery remains evidence of structure only and is
not evidence that platform writes were zero.

## Consequences

Forty-six unrelated observations are outside the executable surface. The
current contract candidate must still pass a separately authorized live read
validation before the real-request-contract gate can be marked passed. Any
required parameter, response-field, host, or image-origin change fails closed
and requires a new development-only discovery; it cannot be learned silently
during a formal sample run.
