// Package dbfs 把 SQL 迁移嵌入二进制,供生产启动时应用。
package dbfs

import "embed"

//go:embed migrations/*.sql
var FS embed.FS
