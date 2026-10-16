module github.com/hayrat/hesabim-sdk-go/examples

go 1.26.0

require (
	github.com/coreos/go-oidc/v3 v3.21.0
	github.com/golang-jwt/jwt/v5 v5.3.1
	github.com/hayrat/hesabim-sdk-go v0.0.0
	github.com/labstack/echo/v4 v4.16.0
	golang.org/x/oauth2 v0.37.0
)

require (
	github.com/go-jose/go-jose/v4 v4.1.4 // indirect
	github.com/labstack/gommon v0.5.0 // indirect
	github.com/mattn/go-colorable v0.1.15 // indirect
	github.com/mattn/go-isatty v0.0.22 // indirect
	github.com/valyala/bytebufferpool v1.0.0 // indirect
	github.com/valyala/fasttemplate v1.2.2 // indirect
	golang.org/x/crypto v0.53.0 // indirect
	golang.org/x/net v0.56.0 // indirect
	golang.org/x/sys v0.46.0 // indirect
	golang.org/x/text v0.40.0 // indirect
)

// Inside this repository the examples build against the SDK next to them.
// When you copy an example into your project, drop this line and run
// `go get github.com/hayrat/hesabim-sdk-go@latest`.
replace github.com/hayrat/hesabim-sdk-go => ../
