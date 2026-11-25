# GitHub Codespaces deployment

This configuration runs the repository's existing HTTP service on port 10000.

Before using the service, add a GitHub Codespaces secret named
`WATERMARKS_SERVER_API_KEY` and grant access only to this repository. Use a
random value of at least 32 characters. Do not put the key in this repository.
The service requires a bearer token for its API.

The Codespaces port is configured as public so an external client can reach it.
The API itself remains bearer-authenticated. Anyone who knows the forwarded URL
can reach the port, but cannot use the API without the secret.

The `postStartCommand` starts the service whenever the Codespace starts.
The forwarded port URL is the API base URL. Append `/health`,
`/capabilities`, `/inspect`, or `/clean` as needed. The HTTP contract matches
the installed `remove-ai-marks` client skill.

The text-rewrite backend is not configured by this deployment. Deterministic
Unicode cleanup and supported file/container metadata operations remain
available subject to the capabilities reported by `/capabilities`.
