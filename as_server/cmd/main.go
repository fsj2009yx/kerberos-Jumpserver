package main

import (
	"flag"
	"os"

	"github.com/fatedier/golib/log"

	"security-project/as_server/config"
	"security-project/as_server/service"
)

func main() {
	configPath := flag.String("config", config.DefaultPath, "path to config json")
	flag.Parse()
	log.Infof("[AS] process starting config=%s", *configPath)
	svc := service.NewService(*configPath)
	if err := svc.Run(); err != nil {
		log.Errorf("[AS] service stopped with error: %v", err)
		os.Exit(1)
	}
}
