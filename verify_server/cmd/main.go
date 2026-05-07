package main

import (
	"flag"
	"log"

	"security-project/verify_server/config"
	"security-project/verify_server/service"
)

func main() {
	configPath := flag.String("config", config.DefaultPath, "path to config json")
	flag.Parse()
	svc := service.NewService(*configPath)
	if err := svc.Run(); err != nil {
		log.Fatal(err)
	}
}
