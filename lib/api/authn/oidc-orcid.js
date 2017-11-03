'use strict'
/**
 * OIDC - ORCiD Relying Party API handler module.
 */

const express = require('express')
const bodyParser = require('body-parser').urlencoded({ extended: false })
//const OidcManager = require('../../models/oidc-manager')
const crypto = require('jsrsasign');
const clientId = "APP-8SEU3HT2XC35A31D";
const orcidCert = {
  "kty": "RSA",
  "e": "AQAB",
  "use": "sig",
  "kid": "sandbox-orcid-org-3hpgosl3b6lapenh1ewsgdob3fawepoj",
  "n": "pl-jp-kTAGf6BZUrWIYUJTvqqMVd4iAnoLS6vve-KNV0q8TxKvMre7oi9IulDcqTuJ1alHrZAIVlgrgFn88MKirZuTqHG6LCtEsr7qGD9XyVcz64oXrb9vx4FO9tLNQxvdnIWCIwyPAYWtPMHMSSD5oEVUtVL_5IaxfCJvU-FchdHiwfxvXMWmA-i3mcEEe9zggag2vUPPIqUwbPVUFNj2hE7UsZbasuIToEMFRZqSB6juc9zv6PEUueQ5hAJCEylTkzMwyBMibrt04TmtZk2w9DfKJR91555s2ZMstX4G_su1_FqQ6p9vgcuLQ6tCtrW77tta-Rw7McF_tyPmvnhQ"
};


const {
  AuthCallbackRequest,
  LogoutRequest,
  SelectProviderRequest
} = require('oidc-auth-manager').handlers


function getOrcidPublicKey() {
  //return crypto.KEYUTIL.getKey(orcidCert);
  return "-----BEGIN CERTIFICATE-----MIIDJjCCAg6gAwIBAgIJAOEuxLSrVzKcMA0GCSqGSIb3DQEBCwUAMBYxFDASBgNVBAMUCyoubG9jYWxob3N0MB4XDTE3MTEwMjE3MzkyMFoXDTI3MTAzMTE3MzkyMFowFjEUMBIGA1UEAxQLKi5sb2NhbGhvc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCtQ1qOXZ7z6gnxowegdtm+oy6dkAbXMLgeKrp/VfGIaUuhfBaQA+/qAuz3vDlvEwIAZnvKAMh7u84IG6hosBZsQUhpUWxOWbv5fLJ4uAB+MNKrAAFbk2atqz6r7pkqjAl8bCRDXOl6wYKoQvR+GH6l575iOz8iKgvmolZCe97ckr0/UR3NGu9BYSF9uEvBezcTLXBDkmoWQblD+msbtqc7jYTuvsOuZapsl3NcUBhVLmlRd663wFZR1zAKCuYYVTpdmIKwaxYcJQN4gl0+cOeHcAqPY06puX/78RObsoFikweOdHAOiLklBmJeIz/2HZnMOK+tD8uGr0c9FnOjEYzJAgMBAAGjdzB1MB0GA1UdDgQWBBSoCfEk1yOeQE0DH/vg81R4m1FXMzBGBgNVHSMEPzA9gBSoCfEk1yOeQE0DH/vg81R4m1FXM6EapBgwFjEUMBIGA1UEAxQLKi5sb2NhbGhvc3SCCQDhLsS0q1cynDAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQCUf7OHkM8epy/g0UFfcSrRo6Jg2zw7AthDLp2ukemZ1QuVSAX1JZJvmxbSIta/op1U1dFCXgmxx/DgeOJW8oBkQiqktlR4Acfnu0dSsFXLGIaJ5tWy6RwSZZn2yMFtbFI+OMCHkBXdjt2jaUg96VTNmx4yVEzlhecXqlhWC3UULFU6lNew4ut+f/5iTHbpkmILK6RQWwpiOtDrEVP5coy8YtabzF5kpm3cMhFErnbE9Zybo5VprcQ/HhpIaKzBmcF/03g6O2ZXweePtjPR+9UeuUwc3ree43XmD5pPdk8UNMt3/z4N6tdM4KPfrDj3Pst+xmBz/1FrMF2HYigJ5SVw-----END CERTIFICATE-----"
}


function verifySignature(idToken) {
  return crypto.KJUR.jws.JWS.verify(idToken, getOrcidPublicKey(), ['RS256']);
  /*
  return crypto.KJUR.jws.JWS.verifyJWT(idToken, getOrcidPublicKey(), {
    alg: ['RS256'],
    iss: ["https:\/\/orcid.org"],
    aud: clientId,
    gracePeriod: 15 * 60 //15 mins skew allowed
  });
  */
}

function extractPayloadAsString(idToken) {
  //return window.atob(idToken.split('.')[1]); //use jwt-decode in deployments
  var contents = crypto.KJUR.jws.JWS.parse(idToken);
  return contents["payloadObj"];
}

function existsOidcTokenHeaders(req) {
  if (req.get("X-OIDC-Token-ID") 
    && req.get("X-OIDC-Token-Issuer")) {
    return true;
  } 
  return false;  
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
  getOrcidPublicKey,
  verifySignature,
  extractPayloadAsString,
  existsOidcTokenHeaders,
  isEmptyToken,
  middleware,
  setAuthenticateHeader,
  statusCodeOverride
}
