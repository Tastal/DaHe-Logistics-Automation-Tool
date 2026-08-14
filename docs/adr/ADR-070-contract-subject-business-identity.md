# ADR-070: Contract subject as Chengfeng business identity

## Context

Chengfeng now serves the same account through two contract subjects. Each subject has the same page structure but an independent waybill population. A waybill identifier or business date can therefore occur under both subjects and cannot remain a global identity.

## Decision

DaHe uses two fixed internal subject codes: `shanxi_guienbo` for 山西贵恩博 and `shanghai_jinyisheng` for 上海晋亿晟.

- Platform Jobs bind one immutable subject in `platform_job_subjects`.
- Snapshots, observations, machine and manual revisions, idempotency records, evidence reuse, history and reports use the subject as part of their identity.
- Existing records created before Schema `0041_contract_subject_scope` are assigned to Shanxi without changing counts, values or evidence hashes.
- The operator's selected subject is a versioned local state. Switching it while idle changes only DaHe's data view and does not navigate or claim the browser.
- Starting a business read makes the single Chengfeng tab select the requested subject using the exact visible control, waits for the new subject response, navigates to the requested business route, performs the cache-disabled read, and confirms the subject again before publication.
- An unknown or unconfirmed subject fails technically. The application never falls back to the other subject or combines their results.

The page-level subject selection is allowed only as a session-context prerequisite for a read. It does not authorize settlement, payment, receipt cancellation or any other Chengfeng business write.

## Consequences

The two companies can be processed through one UI and one browser pipeline without duplicating business modules. Cross-subject records remain isolated even when identifiers and dates match. Browser automation gains one exact subject-selection contract and one additional verification point, while the platform write deny-list remains unchanged.
