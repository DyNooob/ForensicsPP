# Forensics++ static website artifact

This directory contains a built Forensics++ web application. Serve it from the configured site root using a static HTTP(S) server. Client routes without a generated page need SPA fallback to `index.html`; missing JS/WASM paths must not return that fallback.

For a ready-to-run local competition/investigation package, use the complete `offline-static.zip` from the GitHub Release. It includes lookup data, runtime resources, notices and a loopback launcher; it has different network behavior from a website/CDN build.

- Project: [DyNooob/ForensicsPP](https://github.com/DyNooob/ForensicsPP)
- Documentation: [repository docs](https://github.com/DyNooob/ForensicsPP/tree/main/docs)
- Project code: MIT licensed; third-party components/data retain their own terms.

Do not copy only `index.html` away from its supporting resources. Full analysis uses workers and WASM and requires an HTTP origin.
