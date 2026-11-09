import os

import uvicorn

from ledger.server import create_app

if __name__ == "__main__":
    uvicorn.run(
        create_app(),
        host=os.environ.get("LEDGER_HOST", "127.0.0.1"),
        port=int(os.environ.get("LEDGER_PORT", "8001")),
    )
