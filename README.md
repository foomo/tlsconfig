# Golang tls configuration helper

golangs tls package is great, but the default configuration is nothing you should use in production. This package is trying to provide and maintain a set of default tls configurations.

## securing your server

```go
// construct a webserver with a custom tls configuration
tlsServer := &http.Server{
    Addr:      "0.0.0.0:443",
    Handler:   serverHandler,
    TLSConfig: tlsconfig.NewServerTLSConfig(tlsconfig.TLSModeServerStrict),
}

tlsServer.ListenAndServeTLS("path/to/cert", "path/to/key")

```
