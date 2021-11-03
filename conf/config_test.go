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
	fmt.Printf("host=%v, port=%v, db=%v\n", cfg.PostDB.Host, cfg.PostDB.Port, cfg.PostDB.DB)
	fmt.Printf("user=%v, password=%v\n", cfg.PostDB.User, cfg.PostDB.Password)
	fmt.Printf("timeout=%v\n", cfg.PostDB.Timeout)
}
