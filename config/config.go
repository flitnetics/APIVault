package config

import  "github.com/jinzhu/configor"

var Config = struct {
        DB   struct {
                Name     string `default:"api_gateway"`
                Adapter  string `default:"mysql"`
                User     string
                Password string
		Host     string
		Port     int
        }

	Secret  struct {
                Key      string
        }

}{}

func init() {
        if err := configor.Load(&Config, "config/database.yml", "config/secrets.yml"); err != nil {
                panic(err)
        }
}
