package main

import (
	"flag"
	"os"

	"security-project/pkg/utils/log"
	"security-project/tgs_server/config"
	"security-project/tgs_server/service"
)

func main() {
	configPath := flag.String("config", config.DefaultPath, "path to config json")
	flag.Parse()
	log.InitLoggerFromConfigFile(*configPath)
	log.Infof("[TGS] process starting config=%s", *configPath)
	svc := service.NewService(*configPath)
	if err := svc.Run(); err != nil {
		log.Errorf("[TGS] service stopped with error: %v", err)
		os.Exit(1)
	}
}
