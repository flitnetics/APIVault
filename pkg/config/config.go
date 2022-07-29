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

	Jwt  struct {
                Secret      string
		Ttl         int
        }

	UnixSocket       bool `default:"false"`

	Table struct {
                Name     string
		Column struct {
                        Login    string
			Password string
		}
	}
}{}

func init() {
        if err := configor.Load(&Config, "apivault.yml"); err != nil {
                panic(err)
        }
}
