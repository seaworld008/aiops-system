package main

import "log/slog"

func main() {
	slog.Info("workflow worker bootstrap", "status", "ready-for-temporal-configuration")
}
