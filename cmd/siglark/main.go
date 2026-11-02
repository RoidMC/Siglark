package main

import (
	"log/slog"

	"github.com/roidmc/siglark/internal/boot"
)

func main() {
	if err := boot.Run(); err != nil {
		slog.Error("siglark: fatal error", "error", err)
	}
}
