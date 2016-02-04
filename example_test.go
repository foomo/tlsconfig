package tlsconfig_test

import (
	"fmt"

	"github.com/foomo/tlsconfig"

	//"github.com/golang/example/stringutil"
)

func ExampleNewServerTLSConfig_strict() {
	fmt.Println("strict InsecureSkipVerify", tlsconfig.NewServerTLSConfig(tlsconfig.TLSModeServerStrict).InsecureSkipVerify)
	// Output: strict InsecureSkipVerify false
}
