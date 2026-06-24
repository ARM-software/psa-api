<!--
SPDX-FileCopyrightText: Copyright 2018-2026 Arm Limited
SPDX-License-Identifier: Apache-2.0
-->

# Specification Lifecycle Workflows

This guide records occasional workflows for maintaining a PSA API specification that is
built with `psa-api-tool`.

These workflows are separate from the basic setup and build instructions in
`using-psa-api-tool.md`, and from the source editing reference in
`psa-api-tool-notes.md`. They are intended for release managers, specification editors,
and agents doing lifecycle maintenance work.

The sections below are placeholders to be filled in once the publication process and
repository transfer expectations are settled.

## Before Starting Work on a New Issue or Version

Use this workflow after a specification issue or version has been published, and before
the first source changes for the next issue or version are introduced.

Expected topics:

- Decide whether the next work is a new issue of the current version, a release
  candidate, or a new minor/major version.
- Update `doc_info` publication metadata in `conf.py`.
- Update release-history source entries.
- Reset or update draft, quality, issue, and release-candidate metadata.
- Review filename and document identifier expectations.
- Establish the expected API database baseline before semantic changes begin.
- Check whether generated headers, rendered images, or publication artifacts need to be
  reset or regenerated.
- Build the clean starting point and record expected warnings.

TODO: fill in the exact fields and commands once the publication model is confirmed.

## Preparing a Release Candidate

Use this workflow when preparing a candidate build for review before final publication.

Expected topics:

- Set release-candidate metadata in `conf.py`.
- Confirm draft and optional-content settings for the candidate review build.
- Update release notes, current status, potential-for-change, and change-history
  content.
- Run HTML, PDF, API database, generated-header, and image validation as appropriate.
- Review generated filenames and visible title-page/footer metadata.
- Confirm that intentional API changes are reflected in the checked-in API database.
- Record known and accepted warnings.
- Package or tag review artifacts according to the consuming specification repository
  process.

TODO: define exact validation commands and artifact expectations for PSA API
specifications.

## Finalizing an Issue or Version for Publication

Use this workflow when converting an approved release candidate into the final published
issue or version.

Expected topics:

- Remove release-candidate metadata and set final quality/status metadata.
- Confirm draft, watermark, license, copyright, owner, and feedback metadata.
- Finalize release-history, current-status, and potential-for-change sections.
- Verify there are no unresolved rendered TODO, rationale, or comment sections unless
  intentionally published.
- Run final HTML and PDF builds.
- Run final API database comparison and update generated references when required.
- Regenerate rendered image assets when graphics sources changed.
- Review generated filenames, document identifiers, version strings, and title-page
  metadata.
- Create publication artifacts and tags according to the consuming specification
  repository process.

TODO: fill in the exact publication checklist after the release process is agreed.

----

*Copyright 2018-2026 Arm Limited*
