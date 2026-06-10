import uvicorn
import os

if __name__ == "__main__":
    reload = os.environ.get("ENV", "production") == "development"
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 8000)),
        reload=reload,
    )