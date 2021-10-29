package conf

import (
	"fmt"
	"log"
	"testing"
)

func TestInitConfig(t *testing.T) {
	cfg, err := InitConfig("server.yml")
	if err != nil {
		log.Fatalln(err)
	}
	fmt.Printf("host=%v, port=%v, db=%v\n", cfg.PostDb.Host, cfg.PostDb.Port, cfg.PostDb.Db)
	fmt.Printf("user=%v, password=%v\n", cfg.PostDb.User, cfg.PostDb.Password)
	fmt.Printf("timeout=%v\n", cfg.PostDb.Timeout)
}
