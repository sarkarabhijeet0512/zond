package rpc

import (
	"net/http"

	"github.com/gorilla/websocket"
)

// ClientOption is a configuration option for the RPC client.
type ClientOption interface {
	applyOption(*clientConfig)
}

type clientConfig struct {
	httpClient  *http.Client
	httpHeaders http.Header
	httpAuth    HTTPAuth

	wsDialer *websocket.Dialer
}

func (cfg *clientConfig) initHeaders() {
	if cfg.httpHeaders == nil {
		cfg.httpHeaders = make(http.Header)
	}
}

func (cfg *clientConfig) setHeader(key, value string) {
	cfg.initHeaders()
	cfg.httpHeaders.Set(key, value)
}

type optionFunc func(*clientConfig)

func (fn optionFunc) applyOption(opt *clientConfig) {
	fn(opt)
}

// WithWebsocketDialer configures the websocket.Dialer used by the RPC client.
func WithWebsocketDialer(dialer websocket.Dialer) ClientOption {
	return optionFunc(func(cfg *clientConfig) {
		cfg.wsDialer = &dialer
	})
}

// WithHeader configures HTTP headers set by the RPC client. Headers set using this option
// will be used for both HTTP and WebSocket connections.
func WithHeader(key, value string) ClientOption {
	return optionFunc(func(cfg *clientConfig) {
		cfg.initHeaders()
		cfg.httpHeaders.Set(key, value)
	})
}

// WithHeaders configures HTTP headers set by the RPC client. Headers set using this
// option will be used for both HTTP and WebSocket connections.
func WithHeaders(headers http.Header) ClientOption {
	return optionFunc(func(cfg *clientConfig) {
		cfg.initHeaders()
		for k, vs := range headers {
			cfg.httpHeaders[k] = vs
		}
	})
}

// WithHTTPClient configures the http.Client used by the RPC client.
func WithHTTPClient(c *http.Client) ClientOption {
	return optionFunc(func(cfg *clientConfig) {
		cfg.httpClient = c
	})
}

// WithHTTPAuth configures HTTP request authentication. The given provider will be called
// whenever a request is made. Note that only one authentication provider can be active at
// any time.
func WithHTTPAuth(a HTTPAuth) ClientOption {
	if a == nil {
		panic("nil auth")
	}
	return optionFunc(func(cfg *clientConfig) {
		cfg.httpAuth = a
	})
}

// A HTTPAuth function is called by the client whenever a HTTP request is sent.
// The function must be safe for concurrent use.
//
// Usually, HTTPAuth functions will call h.Set("authorization", "...") to add
// auth information to the request.
type HTTPAuth func(h http.Header) error
