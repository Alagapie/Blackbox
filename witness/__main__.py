import os

import uvicorn

from witness.server import create_app

if __name__ == "__main__":
    uvicorn.run(create_app(), host=os.environ.get("WITNESS_HOST", "127.0.0.1"),
                port=int(os.environ.get("WITNESS_PORT", "8002")))
