import os

def _mask_mongo_uri(uri: str) -> str:
	if not uri:
		return "<not set>"
	try:
		# Mask credentials between '://' and '@'
		if '://' in uri and '@' in uri:
			scheme, rest = uri.split('://', 1)
			creds, host = rest.split('@', 1)
			return f"{scheme}://***:***@{host}"
	except Exception:
		pass
	return "<set>"

print(">>> MONGO_URI:", _mask_mongo_uri(os.environ.get("MONGO_URI")))

from app import create_app

app = create_app()
