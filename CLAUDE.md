# Contributing conventions

## No internal work identifiers in tracked files

This repository is public, and `<GenerateDocumentationFile>` is enabled, so every XML doc
comment is compiled into a `.xml` file that is packed inside the published NuGet packages.
Anything written in a `///` comment is shipped documentation, read by people who have no
access to how the work was organised.

Tracked files must therefore never name a unit of internal work or a document that is not in
this repository. That covers codenames built from a letter or number that identify a
development batch, wave, phase, or arc; bare section codes that cite an internal decision log;
anaphoric references to the work item a change belonged to; pointers to a private planning
tree or an off-repository design-note archive; and remarks about who decided something or when
it was done.

A CI step in `.github/workflows/main.yml` enforces this on every build and fails fast when a
match appears in a tracked file. It scans `git ls-files`, so ignored trees are out of scope.

The rule is about identifiers, not about vocabulary. Ordinary technical terms keep their
meaning: batch verification and batch multiplication are cryptographic operations, an
algorithm's own numbered steps are part of the algorithm, and citations to published papers,
RFCs, and FIPS documents by section or appendix are exactly what documentation should contain.

### Removing one correctly

Roughly half of these references are load-bearing: they explain why the code has the shape it
has, and only the source they cite is wrong. Deleting the citation leaves a claim dangling, so
rewrite the sentence into the standing technical statement it implies.

```csharp
//Weak, and still internal: it cites the decision record instead of giving the reason.
//(A literal code cannot be shown here, because the CI step would reject this file too.)
/// Per the recorded convention the mask's univariates match the round polynomials.

//Weak, because deleting the pointer stranded the claim:
/// The mask's univariates match the round polynomials.

//Right, because it says what is true and why it must be:
/// The mask contributes one univariate per sumcheck round, matching the round polynomials
/// degree for degree, so the verifier folds mask and claim together.
```

Never invent a citation to replace one you removed. If the surrounding code and the sources
already cited nearby do not support the statement, write the plain technical sentence with no
citation at all.

## Comment style

Comments state what is true and why, as durable properties of the design. They do not record
history: not when something changed, not what it was called before, not which change
introduced it. That belongs in the commit log, where it stays accurate.

XML doc comments go on every member declaration. Body comments are written `//Text`, with no
space after the slashes. Section-divider and banner comments are not used anywhere.
