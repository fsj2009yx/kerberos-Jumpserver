package main

import (
	"flag"
	"os"

	"security-project/as_server/config"
	"security-project/as_server/service"
	"security-project/pkg/utils/log"
)

func main() {
	configPath := flag.String("config", config.DefaultPath, "path to config json")
	flag.Parse()
	log.InitLoggerFromConfigFile(*configPath)
	log.Infof("[AS] process starting config=%s", *configPath)
	svc := service.NewService(*configPath)
	if err := svc.Run(); err != nil {
		log.Errorf("[AS] service stopped with error: %v", err)
		os.Exit(1)
	}
}
