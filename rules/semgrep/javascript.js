// Static Semgrep fixtures for supported JavaScript idioms.
const OAuth2Strategy = require("passport-oauth2");
const jwt = require("jsonwebtoken");

function redirect(req, res) {
  // ruleid: actionhound-js-oauth-redirect
  return res.redirect(req.query.redirect_uri);
}

function registeredRedirect(res) {
  // ok: actionhound-js-oauth-redirect
  return res.redirect("https://example.invalid/registered");
}

// ruleid: actionhound-js-oauth-state
new OAuth2Strategy({
  authorizationURL: "https://example.invalid/authorize",
  tokenURL: "https://example.invalid/token",
}, verify);

// ok: actionhound-js-oauth-state
new OAuth2Strategy({
  authorizationURL: "https://example.invalid/authorize",
  tokenURL: "https://example.invalid/token",
  state: true,
}, verify);

function token(value, key) {
  // ruleid: actionhound-js-jwt-weak-validation
  jwt.verify(value, key, {algorithms: ["none"]});
  // ok: actionhound-js-jwt-weak-validation
  jwt.verify(value, key, {algorithms: ["RS256"]});
}

function lookup(req, tenant) {
  // ruleid: actionhound-js-unscoped-object-lookup
  Document.findById(req.params.id);
  // ok: actionhound-js-unscoped-object-lookup
  Document.findOne({_id: req.params.id, tenant});
}

function outbound(req) {
  // ruleid: actionhound-js-ssrf
  fetch(req.query.destination);
  // ok: actionhound-js-ssrf
  fetch("https://example.invalid/");
}

// ruleid: static-oauth-state
new URLSearchParams({state: "fixed"});

function authorize(sessionState) {
  // ok: static-oauth-state
  return new URLSearchParams({state: sessionState});
}
