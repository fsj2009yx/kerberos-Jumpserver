package main

import (
	"flag"
	"os"

	"github.com/fatedier/golib/log"

	"security-project/verify_server/config"
	"security-project/verify_server/service"
)

func main() {
	configPath := flag.String("config", config.DefaultPath, "path to config json")
	flag.Parse()
	log.Infof("[V] process starting config=%s", *configPath)
	svc := service.NewService(*configPath)
	if err := svc.Run(); err != nil {
		log.Errorf("[V] service stopped with error: %v", err)
		os.Exit(1)
	}
}
