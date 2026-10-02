# Evidence tools

`indicators.py` normalizes hosts and extracts sender/URL indicators without connecting to suspicious sites. Correlation is exact-host matching; this is intentionally a small demo, not a general campaign clustering engine.

`enrichment.py` uses the labeled synthetic fixture in `samples/threat_intel.json`. Optional Serper queries are limited to two public hostnames per investigation. Search snippets are untrusted context, never a reputation verdict or execution input. Network failures become unavailable enrichment instead of aborting local analysis.
