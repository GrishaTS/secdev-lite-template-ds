import html

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, PlainTextResponse
from fastapi.templating import Jinja2Templates

app = FastAPI()
templates = Jinja2Templates(directory="app/templates")


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    csp = (
        "default-src 'self'; "
        "script-src 'self'; "
        "object-src 'none'; "
        "base-uri 'self'; "
        "frame-ancestors 'none'; "
        "form-action 'self'"
    )
    response.headers.setdefault(
        "Cache-Control",
        "no-store, no-cache, must-revalidate, max-age=0"
    )
    response.headers.setdefault("Pragma", "no-cache")
    response.headers.setdefault("Expires", "0")
    response.headers.setdefault("Content-Security-Policy", csp)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("X-XSS-Protection", "1; mode=block")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("Permissions-Policy", "geolocation=(), microphone=()")
    response.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
    response.headers.setdefault("Cross-Origin-Embedder-Policy", "require-corp")
    response.headers.setdefault("Cross-Origin-Resource-Policy", "same-origin")
    return response


@app.get("/", response_class=HTMLResponse)
def index(request: Request, q: str = ""):
    # намеренно простая страница, отражающая ввод
    # (для DAST это даст находки типа отражений/хедеров)
    return templates.TemplateResponse(
        "index.html",
        {"request": request, "q": q}
    )

@app.get("/healthz")
def healthz():
    return PlainTextResponse("OK")

@app.get("/echo", response_class=HTMLResponse)
def echo(x: str = ""):
    # экранируем пользовательский ввод, чтобы избежать XSS
    safe_text = html.escape(x, quote=True)
    return HTMLResponse(f"<h1>ECHO</h1><div>you said: {safe_text}</div>")
