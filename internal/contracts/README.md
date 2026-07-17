# Generated internal contracts

The sole Go destination for P02-generated protocol and schema types. Contract packages may depend on the standard library and other generated contract packages, never implementation packages.

`internal/contracts/quality/sanitizedtrajectory` is the one explicit trajectory-input package allowed across the quality boundary. P02 must generate it from the accepted sanitized contract before quality implementation imports it; raw or general-purpose trajectory types are not substitutes.
