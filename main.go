package main

import (
	"log"

	"github.com/bittensor-nexus/auth/internal/auth"
	"github.com/bittensor-nexus/auth/internal/configuration"
)

func main() {
	// Initialize configuration
	config := configuration.NewConfig()

	// Create and start the auth server
	authServer := auth.NewAuth(config)

	if err := authServer.Start(); err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}
