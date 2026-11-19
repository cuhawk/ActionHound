"""Static Semgrep fixtures for supported Python idioms."""

import jwt
import requests
from fastapi import FastAPI
from fastapi.responses import RedirectResponse

app = FastAPI()


def redirects(request):
    # ruleid: actionhound-python-oauth-redirect
    return RedirectResponse(request.query_params["redirect_uri"])


def registered_redirect():
    # ok: actionhound-python-oauth-redirect
    return RedirectResponse("https://example.invalid/registered")


@app.get("/oauth/callback")
async def callback(code: str):
    # ruleid: actionhound-python-oauth-state
    return await client.fetch_token(code=code)


@app.get("/oauth/callback")
async def callback_with_state(code: str, state: str):
    verify_session_state(state)
    # ok: actionhound-python-oauth-state
    return await client.fetch_token(code=code)


def token(encoded):
    # ruleid: actionhound-python-jwt-weak-validation
    jwt.decode(encoded, options={"verify_signature": False})


def verified_token(encoded, key):
    # ok: actionhound-python-jwt-weak-validation
    jwt.decode(encoded, key, algorithms=["RS256"])


def lookup(request, session):
    object_id = request.path_params["object_id"]
    # ruleid: actionhound-python-unscoped-object-lookup
    return session.get(Document, object_id)


def scoped_lookup(request, session, tenant):
    # ok: actionhound-python-unscoped-object-lookup
    return session.query(Document).filter_by(id=request.path_params["id"], tenant_id=tenant)


def outbound(request):
    destination = request.query_params["destination"]
    # ruleid: actionhound-python-ssrf
    return requests.get(destination)


def fixed_outbound():
    # ok: actionhound-python-ssrf
    return requests.get("https://example.invalid/")
