'use strict'
/**
 * OIDC - ORCiD Relying Party API handler module.
 */

const express = require('express')
const bodyParser = require('body-parser').urlencoded({ extended: false })
const request = require("request");
const crypto = require('jsrsasign');
const li = require("li");
var debug = require('../../debug.js').oidcOrcid;

const clientId = "APP-8SEU3HT2XC35A31D";
const orcidCert = {
  "kty": "RSA",
  "e": "AQAB",
  "use": "sig",
  "kid": "production-orcid-org-7hdmdswarosg3gjujo8agwtazgkp1ojs",
  "n": "jxTIntA7YvdfnYkLSN4wk__E2zf_wbb0SV_HLHFvh6a9ENVRD1_rHK0EijlBzikb-1rgDQihJETcgBLsMoZVQqGj8fDUUuxnVHsuGav_bf41PA7E_58HXKPrB2C0cON41f7K3o9TStKpVJOSXBrRWURmNQ64qnSSryn1nCxMzXpaw7VUo409ohybbvN6ngxVy4QR2NCC7Fr0QVdtapxD7zdlwx6lEwGemuqs_oG5oDtrRuRgeOHmRps2R6gG5oc-JqVMrVRv6F9h4ja3UgxCDBQjOVT1BFPWmMHnHCsVYLqbbXkZUfvP2sO1dJiYd_zrQhi-FtNth9qrLLv3gkgtwQ"
};


const {
  AuthCallbackRequest,
  LogoutRequest,
  SelectProviderRequest
} = require('oidc-auth-manager').handlers


function getOrcidPublicKey(idToken, callback) {
  return crypto.KEYUTIL.getKey(orcidCert);
}

function getPublicKeyAndVerifySign(idToken) {
  request.get("https://orcid.org/.well-known/openid-configuration",
  function(err, res, body) {
    var oidc_conf = JSON.parse(body);
    var jwks_url = oidc_conf["jwks_uri"];

    request.get(jwks_url, function(err1, res1, body1) {
      var orcid_key = JSON.parse(body1);
      var pubKey = crypto.KEYUTIL.getKey(orcid_key["keys"][0]);
      return callback(idToken, pubKey);
    });

  });
  var v = getOrcidPublicKey(idToken, verifySignature);
  return v;
}

function verifySignature(idToken) {
  debug("verifying token");
  if (!idToken || idToken == "undefined") {
    debug("no token found");
    return false;
  }
  var verified = crypto.KJUR.jws.JWS.verify(idToken, getOrcidPublicKey(), ['RS256']);
  return verified;
}

function extractPayloadAsString(idToken) {
  var contents = crypto.KJUR.jws.JWS.parse(idToken);
  return contents["payloadObj"];
}

function getOidcTokenAndIssuer(req) {
  var idToken = req.get("X-OIDC-Token-ID");
  var linkHeader = req.get("Link");
  var links = li.parse(linkHeader);
  var issuer;
  for (var rel in links) {
    if (rel == "http://openid.net/specs/connect/1.0/issuer") {
      issuer = links[rel];
    }
  }
  return {"issuer": issuer, "idToken": idToken};
}

function getUserIdUsingOidc(req) {
  var userId = null;
  var tokens = getOidcTokenAndIssuer(req);
  var idToken = tokens["idToken"];
  var tokenIssuer = tokens["issuer"];
  debug("idToken: " + idToken);
  debug("tokenIssuer: " + tokenIssuer);
  if (!idToken || !tokenIssuer) {
    debug("idToken or tokenIssuer missing. no user found.");
    return userId;
  }
  debug("Found OIDC X Headers")
  debug("ID Token: " + idToken);
  debug("token issuer: " + tokenIssuer);

  if (verifySignature(idToken)) {
    debug("Signature Verified.");
    var contents = extractPayloadAsString(idToken);
    debug("token contents: "+ JSON.stringify(contents));
    var orcid = contents["sub"];
    if (!orcid.startsWith("http")) {
      orcid = "https://orcid.org/" + orcid;
    }
    userId = orcid;
  }
  else {
    debug("Invalid Token!");
  }
  return userId;
}

/**
 * Returns a router with OIDC Relying Party and Identity Provider middleware:
 *
 * @method middleware
 *
 * @param oidc {OidcManager}
 *
 * @return {Router} Express router
 */
function middleware (oidc) {
  const router = express.Router('/')

  return router
}

/**
 * Sets the `WWW-Authenticate` response header for 401 error responses.
 * Used by error-pages handler.
 *
 * @param req {IncomingRequest}
 * @param res {ServerResponse}
 * @param err {Error}
 */
function setAuthenticateHeader (req, res, err) {
  let locals = req.app.locals

  let errorParams = {
    realm: locals.host.serverUri,
    scope: 'openid webid',
    error: err.error,
    error_description: err.error_description,
    error_uri: err.error_uri
  }

  let challengeParams = Object.keys(errorParams)
    .filter(key => !!errorParams[key])
    .map(key => `${key}="${errorParams[key]}"`)
    .join(', ')

  res.set('WWW-Authenticate', 'Bearer ' + challengeParams)
}

/**
 * Provides custom logic for error status code overrides.
 *
 * @param statusCode {number}
 * @param req {IncomingRequest}
 *
 * @returns {number}
 */
function statusCodeOverride (statusCode, req) {
  if (isEmptyToken(req)) {
    return 400
  } else {
    return statusCode
  }
}

/**
 * Tests whether the `Authorization:` header includes an empty or missing Bearer
 * token.
 *
 * @param req {IncomingRequest}
 *
 * @returns {boolean}
 */
function isEmptyToken (req) {
  let header = req.get('Authorization')

  if (!header) { return false }

  if (header.startsWith('Bearer')) {
    let fragments = header.split(' ')

    if (fragments.length === 1) {
      return true
    } else if (!fragments[1]) {
      return true
    }
  }

  return false
}

module.exports = {
  getUserIdUsingOidc,
  isEmptyToken,
  middleware,
  setAuthenticateHeader,
  statusCodeOverride
}
