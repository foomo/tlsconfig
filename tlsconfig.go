// Lightweight tls configuration package.
package tlsconfig

import "crypto/tls"

// TLSModeServer a type to define server tls config
type TLSModeServer string

const (
	// TLSModeServerStrict - this is serious and we do not mind loosing clients
	// (= Mozilla "modern" compatibility). Compatible clients have versions
	// equal or greater than Firefox 27, Chrome 22, IE 11, Opera 14, Safari 7,
	// Android 4.4, Java 8
	TLSModeServerStrict TLSModeServer = "strict"
	// TLSModeServerLoose - ecommerce compromise
	// Compatible clients (>=): Firefox 1, Chrome 1, IE 7, Opera 5, Safari 1,
	// Windows XP IE8, Android 2.3, Java 7
	TLSModeServerLoose = "loose"
	// TLSModeServerDefault - standard crypto/tls.Config untouched
	// highly compatible and insecure
	TLSModeServerDefault = "default"
)

// NewServerTLSConfig - server tls config
func NewServerTLSConfig(mode TLSModeServer) *tls.Config {
	c := &tls.Config{}
	switch mode {
	case TLSModeServerDefault:
		// will not touch this one, but trust the golang team
	case TLSModeServerLoose:
		c.MinVersion = tls.VersionTLS10
		c.CipherSuites = []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_RSA_WITH_AES_128_CBC_SHA256,
			tls.TLS_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		}
		c.CurvePreferences = []tls.CurveID{
			tls.CurveP256,
			tls.CurveP384,
			tls.CurveP521,
		}
	case TLSModeServerStrict:
		c.MinVersion = tls.VersionTLS12
		c.PreferServerCipherSuites = true
		c.CipherSuites = []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
		}
		c.CurvePreferences = []tls.CurveID{
			tls.CurveP256,
			tls.CurveP384,
			tls.CurveP521,
		}
	}
	return c
}
