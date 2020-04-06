/*
Copyright 2015 All rights reserved.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/coreos/go-oidc/jose"
	"go.uber.org/zap"
)

// filterCookies is responsible for censoring any cookies we don't want sent
func filterCookies(req *http.Request, filter []string) error {
	// @NOTE: there doesn't appear to be a way of removing a cookie from the http.Request as
	// AddCookie() just append
	cookies := req.Cookies()
	// @step: empty the current cookies
	req.Header.Set("Cookie", "")
	// @step: iterate the cookies and filter out anything we
	for _, x := range cookies {
		var found bool
		// @step: does this cookie match our filter?
		for _, n := range filter {
			if strings.HasPrefix(x.Name, n) {
				req.AddCookie(&http.Cookie{Name: x.Name, Value: "censored"})
				found = true
				break
			}
		}
		if !found {
			req.AddCookie(x)
		}
	}

	return nil
}

// revokeProxy is responsible to stopping the middleware from proxying the request
func (r *oauthProxy) revokeProxy(w http.ResponseWriter, req *http.Request) context.Context {
	var scope *RequestScope
	sc := req.Context().Value(contextScopeName)
	switch sc {
	case nil:
		scope = &RequestScope{AccessDenied: true}
	default:
		scope = sc.(*RequestScope)
	}
	scope.AccessDenied = true

	return context.WithValue(req.Context(), contextScopeName, scope)
}

// accessForbidden redirects the user to the forbidden page
func (r *oauthProxy) accessForbidden(w http.ResponseWriter, req *http.Request) context.Context {
	w.WriteHeader(http.StatusForbidden)
	// are we using a custom http template for 403?
	if r.config.hasCustomForbiddenPage() {
		name := path.Base(r.config.ForbiddenPage)
		if err := r.Render(w, name, r.config.Tags); err != nil {
			r.log.Error("failed to render the template", zap.Error(err), zap.String("template", name))
		}
	}

	return r.revokeProxy(w, req)
}

// redirectToURL redirects the user and aborts the context
func (r *oauthProxy) redirectToURL(url string, w http.ResponseWriter, req *http.Request, statusCode int) context.Context {
	w.Header().Add("Cache-Control", "no-cache, no-store, must-revalidate, max-age=0")
	http.Redirect(w, req, url, statusCode)

	return r.revokeProxy(w, req)
}

// redirectToAuthorization redirects the user to authorization handler
func (r *oauthProxy) redirectToAuthorization(w http.ResponseWriter, req *http.Request) context.Context {

	if r.config.NoRedirects || (r.config.EnableXNoRedirectsHeader && ("" != req.Header.Get("X-Auth-NoRedirects"))) {
		r.log.Warn("Redirecting for authorization is not supported for this request")
		w.WriteHeader(http.StatusUnauthorized)

		// RFC7235 requires a WWW-Authenticate header containing a challenge applicable to the requested resource.
		// See: https://tools.ietf.org/html/rfc7235
		w.Header().Set("WWW-Authenticate", fmt.Sprintf("Bearer realm=\"%s\", error=\"missing_token\", error_description=\"oauth redirects disallowed\"", r.config.DiscoveryURL))

		// are we using a custom http template for 401?
		if r.config.UnauthorizedPage != "" {
			name := path.Base(r.config.UnauthorizedPage)
			if err := r.Render(w, name, r.config.Tags); err != nil {
				r.log.Error("failed to render the template", zap.Error(err), zap.String("template", name))
			}
		}

		return r.revokeProxy(w, req)
	}

	// step: add a state referrer to the authorization page
	//	uuid := r.writeStateParameterCookie(req, w)
	//	authQuery := fmt.Sprintf("?state=%s", uuid)
	//	r.log.Debug("RRRRRRRRRRRR", zap.String("request", req.URL.String()))

	state := req.URL.RequestURI()
	if r.config.EnableXForwardedState {
		// Assemble the state referrer URL from the X-Forwarded-* headers
		forwardedUri := req.Header.Get("X-Forwarded-URI")
		if forwardedUri != "" {
			r.log.Debug("Checking X-forwarded path headers",
				zap.String("forwardedUri", forwardedUri))
			state = forwardedUri
		}
		forwardedPrefix := req.Header.Get("X-Forwarded-Prefix")
		if forwardedPrefix != "" {
			r.log.Debug("Checking X-forwarded path headers",
				zap.String("forwardedPrefix", forwardedPrefix))
			state = fmt.Sprintf("%s%s", strings.TrimRight(forwardedPrefix, "/"), state)
		}
		forwardedHost := req.Header.Get("X-Forwarded-Host")
		if forwardedHost != "" {
			forwardedScheme := defaultTo(req.Header.Get("X-Forwarded-Proto"), req.URL.Scheme)
			forwardedPort := req.Header.Get("X-Forwarded-Port")
			if !strings.Contains(forwardedHost, ":") && forwardedPort != "" {
				state = fmt.Sprintf("%s://%s:%s%s", forwardedScheme, forwardedHost, forwardedPort, state)
			} else {
				state = fmt.Sprintf("%s://%s%s", forwardedScheme, forwardedHost, state)
			}
		}
		_, err := url.ParseRequestURI(state)
		if err == nil {
			r.log.Debug("Assembled state referrer URL from X-Forwarded-* headers",
				zap.String("state", state))

		} else {
			r.log.Warn("The X-Forwarded-* headers could not be assembled to a valid state referrer URL",
				zap.String("state", state),
				zap.Error(err))
			state = req.URL.RequestURI()
		}
	}

	authQuery := fmt.Sprintf("?state=%s", base64.StdEncoding.EncodeToString([]byte(state)))
	r.log.Debug("setting state cookie:", zap.String("state", state), zap.String("authQuery", authQuery))

	// step: if verification is switched off, we can't authorization
	if r.config.SkipTokenVerification {
		r.log.Error("refusing to redirection to authorization endpoint, skip token verification switched on")
		w.WriteHeader(http.StatusForbidden)
		return r.revokeProxy(w, req)
	}
	if r.config.InvalidAuthRedirectsWith303 {
		r.redirectToURL(r.config.WithOAuthURI(authorizationURL+authQuery), w, req, http.StatusSeeOther)
	} else {
		r.redirectToURL(r.config.WithOAuthURI(authorizationURL+authQuery), w, req, http.StatusTemporaryRedirect)
	}

	return r.revokeProxy(w, req)
}

// getAccessCookieExpiration calculates the expiration of the access token cookie
func (r *oauthProxy) getAccessCookieExpiration(token jose.JWT, refresh string) time.Duration {
	// notes: by default the duration of the access token will be the configuration option, if
	// however we can decode the refresh token, we will set the duration to the duration of the
	// refresh token
	duration := r.config.AccessTokenDuration
	if _, ident, err := parseToken(refresh); err == nil {
		delta := time.Until(ident.ExpiresAt)
		if delta > 0 {
			duration = delta
		}
		r.log.Debug("parsed refresh token with new duration", zap.Duration("new duration", delta))
	} else {
		r.log.Debug("refresh token is opaque and cannot be used to extend calculated duration")
	}

	return duration
}

// MergUri parses the 2 URI strings, and merges in baseUri host:port/prefix to avoid making a https://host:port/https://host:port/strng mess
func MergeUri(baseURI, resultURI string) *url.URL {
	base, _ := url.Parse(baseURI)
	result, _ := url.Parse(resultURI)
	if base.Host != "" { // this has the port in it
		result.Scheme = base.Scheme
		result.Host = base.Host
	}
	if base.Path != "" {
		if strings.HasSuffix(base.Path, "/") || strings.HasPrefix(result.Path, "/") {
			result.Path = fmt.Sprintf("%s%s", base.Path, result.Path)
		} else {
			result.Path = fmt.Sprintf("%s/%s", base.Path, result.Path)
		}
	}

	return result
}
