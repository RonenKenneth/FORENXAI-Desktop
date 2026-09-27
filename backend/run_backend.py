def main():
    # Imported here so the --supervise parent stays a light process.
    import uvicorn

    from app.main import app

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


def supervise():
    # Native crashes (for example 0xC0000409 inside xgboost.dll) kill the
    # whole interpreter, so a try/except cannot catch them. Run the server
    # as a child and start it again whenever it dies with an error.
    import subprocess
    import sys
    import time

    while True:
        code = subprocess.call([sys.executable, __file__])
        if code == 0:
            return
        print(
            f"[FORENXAI] Backend exited with code {code}; restarting in 3 s...",
            flush=True
        )
        time.sleep(3)


if __name__ == "__main__":
    import sys

    if "--supervise" in sys.argv:
        supervise()
    else:
        main()