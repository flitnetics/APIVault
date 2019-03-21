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

}{}

func init() {
        if err := configor.Load(&Config, "config/database.yml"); err != nil {
                panic(err)
        }
}
