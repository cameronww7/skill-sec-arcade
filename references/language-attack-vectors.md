# Language / runtime → common attack vectors

Quick lookup for `code-threat-mapper` Step 6. Only surface a vector here if the codebase actually has supporting code for it (an import, a pattern, a config). This is a list to check against, not a list to dump wholesale into a report.

| Language / runtime | Common attack vectors |
|---|---|
| JavaScript / Node.js | Prototype pollution (merging untrusted objects into existing ones), ReDoS from unbounded regex on user input, insecure use of `eval`/`Function`/`vm` on untrusted strings, NoSQL injection via unsanitized query objects, dependency confusion via `package.json` |
| TypeScript | Same as JavaScript/Node.js underneath the type layer, types are erased at runtime and don't prevent injection, prototype pollution, or unsafe deserialization |
| Python | Insecure deserialization via `pickle`/`yaml.load` (use `safe_load`), server-side template injection (SSTI) in Jinja2/Mako when user input reaches a template string, `eval`/`exec` on untrusted input, path traversal via unsanitized `os.path.join` |
| Java / JVM | Deserialization gadget chains (`ObjectInputStream` on untrusted data), XXE via misconfigured XML parsers, Expression Language (EL) injection, unsafe reflection, JNDI injection (Log4Shell-style) |
| Go | SSRF via HTTP clients that follow redirects or accept arbitrary host input, command injection via `os/exec` with unsanitized arguments, path traversal from unchecked `filepath.Join`, missing context timeouts enabling resource exhaustion |
| PHP | Local/remote file inclusion (LFI/RFI) via unsanitized `include`/`require` paths, PHP object injection via `unserialize()`, type juggling in loose comparisons (`==`), path traversal in file upload handlers |
| Ruby / Rails | Mass assignment exposing unintended model attributes, unsafe YAML deserialization (`YAML.load` vs `YAML.safe_load`), ERB server-side template injection, command injection via backticks or `system()` with unsanitized input |
| C / C++ | Buffer overflows from unchecked memory copies (`strcpy`, `memcpy`), use-after-free and double-free, format string vulnerabilities (`printf(user_input)`), integer overflow leading to undersized allocations |
| C# / .NET | Insecure deserialization (`BinaryFormatter`), XXE in XML parsing, LDAP/SQL injection via string-concatenated queries, path traversal in file APIs |

Cross-check the languages/frameworks detected in Step 1 against this table. Only include a row's vectors in the output if the codebase has actual code that could exercise them (the specific import, sink, or pattern), and cite it by file:line same as everything else.
