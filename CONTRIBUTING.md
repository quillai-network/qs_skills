# Contributing to QuillShield Security Skills

Thank you for your interest in contributing. This document explains how to propose changes, add or improve skills, and work with the repository.

## Code of Conduct

By participating, you agree to uphold our [Code of Conduct](CODE_OF_CONDUCT.md).

## How to Contribute

### Reporting bugs or suggesting improvements

- **Bugs** (e.g. incorrect methodology, broken links, typos in skills): open an [issue](https://github.com/quillai-network/qs_skill/issues) with the **bug report** template.
- **Ideas** (new checks, new references, new plugins): use the **feature request** template.

### Contributing content

We welcome:

- **Edits to existing skills** — clearer wording, new detection steps, updated references.
- **New reference material** — case studies, patterns, or checklists under a skill’s `references/` folder.
- **New plugins** — additional skills following the same layout (see below).

## Development setup

1. Fork and clone the repo:
   ```bash
   git clone https://github.com/YOUR_USERNAME/qs_skill.git
   cd qs_skill
   ```
2. Create a branch for your change:
   ```bash
   git checkout -b fix/your-change   # or feat/your-feature
   ```
3. Edit files (see [Skill structure](#skill-structure) and [Conventions](#conventions)).
4. Run any checks (e.g. markdown lint if we add it).
5. Commit with a clear message and open a pull request.

## Skill structure

Each plugin lives under `plugins/<plugin-name>/` and should have:

- **`.claude-plugin/plugin.json`** — `name`, `version`, `description`, `author`.
- **`README.md`** — Short description, when to use, and link to the skill.
- **`skills/<skill-name>/`**
  - **`SKILL.md`** — Main skill: when to use, steps, checklists, severity guidance.
  - **`references/`** — Supporting docs (e.g. `*.md` for patterns, case studies, checklists).

To add a new plugin to the marketplace, add its path to the `plugins` array in `.claude-plugin/marketplace.json`.

## Conventions

- **Markdown**: Use clear headings, lists, and code blocks. Keep line length readable (e.g. wrap around 100–120 characters if desired).
- **Terminology**: Prefer established terms (e.g. OWASP, CEI, EIP-712) and link to specs or references where helpful.
- **Severity**: Align with the [Multi-Layer Severity Matrix](README.md#multi-layer-severity-matrix) when adding or changing severity guidance.
- **References**: Prefer open, citable sources (EIPs, OWASP, audit reports, public post-mortems). Avoid internal-only or paywalled links when possible.

## Pull request process

1. **Scope**: One logical change per PR (one skill update, one new reference, one new plugin, etc.).
2. **Description**: Use the PR template. Describe what changed and why; reference any related issues.
3. **Review**: Maintainers will review for accuracy, consistency with existing skills, and adherence to this guide.
4. **Merge**: After approval, a maintainer will merge. You’ll be credited in the repo history and release notes when applicable.

## Questions

If something is unclear, open a [Discussion](https://github.com/quillai-network/qs_skill/discussions) or an issue and we’ll help.

Thank you for contributing to QuillShield Security Skills.
