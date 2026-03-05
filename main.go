package main

import (
	"log"

	handler "gitlab.com/secondstarcavalier/controlplane/services/fleetwood/internal"
	servicemanager "gitlab.com/secondstarcavalier/controlplane/services/fleetwood/tacplus/service-manager"
)

func main() {
	sm, err := servicemanager.New()
	if err != nil {
		log.Fatalf("servicemanager: %v", err)
	}

	h, err := handler.NewHandler(sm.Backends())
	if err != nil {
		log.Fatalf("handler: %v", err)
	}

	if err := sm.Run(h); err != nil {
		log.Fatalf("fleetwood: %v", err)
	}
}
