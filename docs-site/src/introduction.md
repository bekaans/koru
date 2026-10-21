# Introduction

Koru is a deception-based runtime security tool for Linux servers. It plants honeytokens (decoy credentials, fake SSH keys, decoy `.env` and MCP configuration files) and detects access to them at kernel level with eBPF, before any credential is used, and attributes the access to a process lineage (human, AI agent, possibly hijacked AI agent).

Start with the Quick start, then Concepts. Honest limits: see the repository README ("What Koru is not").
