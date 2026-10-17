# Third-party components

ConfigTool.exe bundles or links the components below. Each keeps its own license.

| Component | Version | License | Source |
|---|---|---|---|
| Python (python-build-standalone) | 3.12.15, release 20261013 | PSF License | https://github.com/astral-sh/python-build-standalone |
| Xray-core | v26.3.27 | MPL-2.0 | https://github.com/XTLS/Xray-core |
| sing-box | v1.14.2 | GPL-3.0-or-later, with an added clause: derivative works may not use the name or imply association with the application without prior consent | https://github.com/SagerNet/sing-box |
| go-webview2 (launcher) | 56598839c808 | MIT | https://github.com/jchv/go-webview2 |
| go-winloader (launcher) | c1995be93bd1 | ISC | https://github.com/jchv/go-winloader |
| golang.org/x/sys (launcher) | v0.20.0 | BSD-3-Clause | https://cs.opensource.google/go/x/sys |

The exact xray and sing-box binaries are downloaded unmodified from their official release pages by `scripts/build-windows.sh`. Their license files are included next to the binaries inside the exe (`xray/LICENSE`, `singbox/LICENSE`). The corresponding source of sing-box is available at the repository above, at the tag listed.

Bundled data: the IP blocklist is generated from the public lists "ipsum" (stamparm/ipsum) and "FireHOL level1" (firehol/blocklist-ipsets).
