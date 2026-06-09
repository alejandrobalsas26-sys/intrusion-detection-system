from dashboard import create_app

if __name__ == "__main__":
    app = create_app()
    # Bound to localhost only to prevent accidental external exposure
    app.run(host="127.0.0.1", port=5000)
