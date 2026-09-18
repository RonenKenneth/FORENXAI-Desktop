from app.main import app

import uvicorn


def main():
    print(
        "========================================",
        flush=True
    )

    print(
        "FORENXAI Backend Starting...",
        flush=True
    )

    print(
        "Address: http://127.0.0.1:8000",
        flush=True
    )

    print(
        "========================================",
        flush=True
    )

    uvicorn.run(
        app,
        host="127.0.0.1",
        port=8000,
        log_level="info",
        reload=False
    )


if __name__ == "__main__":
    main()