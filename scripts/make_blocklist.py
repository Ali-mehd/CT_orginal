"""Generate the bundled blocklist.txt from the public lists, using the app's own normalizer."""
import os
import sys
import urllib.request

sys.path.insert(0, "app")
import cfgscan  # noqa: E402

texts = [urllib.request.urlopen(u, timeout=60).read().decode("utf-8", "replace") for u in cfgscan.BLOCK_SOURCES]
out = os.path.join(os.environ["PAYLOAD_APP"], "blocklist.txt")
with open(out, "w", encoding="utf-8") as f:
    f.write(cfgscan.normalize_blocklist(*texts))
print("blocklist written:", out)
