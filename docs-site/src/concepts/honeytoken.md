# What is a honeytoken?

A honeytoken is a decoy credential or file that no legitimate process should touch; any access is a high-signal alert. Koru detects the *read* on the host (access detection), which differs from tools that alert when the credential is *used* elsewhere.
