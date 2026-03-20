package main

import (
	"log"

	handler "gitlab.com/secondstarcavalier/controlplane/services/sentinel/internal"
	servicemanager "gitlab.com/secondstarcavalier/controlplane/services/sentinel/tacplus/s2sm"
)

func main() {
	sm, err := servicemanager.New()
	if err != nil {
		log.Fatalf("servicemanager: %v", err)
	}

	h, err := handler.NewHandler(sm)
	if err != nil {
		log.Fatalf("handler: %v", err)
	}

	if err := sm.Run(h); err != nil {
		log.Fatalf("sentinel: %v", err)
	}
}
