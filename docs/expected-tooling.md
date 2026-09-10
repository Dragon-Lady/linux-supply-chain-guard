# Expected startup tooling

The operator has approved normal startup activity from TanStack DB, xAI,
OpenAI, and Claude/Anthropic tooling. This is an expected-use note, not a
blanket allowlist.

A scanner may suppress an expected-tooling alert only after correlating the
installed artifact, owning process, configured command or extension ID, and an
official provider destination. A new executable path, signer, package version,
native-messaging host, endpoint, or unexpected child process must remain
visible for review until the operator approves that exact change.

The observed `com.openai.codexextension` browser native-messaging manifest,
ChatGPT extension `hehggadaopoacecdllhhajmbjkdcmajg` version
`1.26.901.11451`, and Claude extension
`fcoeoabgfenejglbffodgkkbkcdhcgfn` version `1.0.91` are recognized as expected
startup tooling. The Claude extension identity is independently listed by the
[Chrome Web Store](https://chromewebstore.google.com/detail/claude/fcoeoabgfenejglbffodgkkbkcdhcgfn).
TanStack DB, xAI, and Claude tooling remain expected-but-verify until their
other exact local artifacts are observed and recorded. The guard does not
collect or upload usage data.
