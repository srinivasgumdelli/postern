// Package deps pins third-party modules while packages are built in
// parallel. Removed once every dependency has a real importer.
package deps

import (
	_ "github.com/modelcontextprotocol/go-sdk/mcp"
	_ "golang.org/x/crypto/nacl/box"
	_ "modernc.org/sqlite"
)
