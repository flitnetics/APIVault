package db

import (
        "log"
        "fmt"

        "github.com/jinzhu/gorm"
        _ "github.com/jinzhu/gorm/dialects/mysql"
        _ "github.com/jinzhu/gorm/dialects/postgres"
        _ "github.com/jinzhu/gorm/dialects/mssql"
        "APIVault/pkg/config"
)

var DBCon *gorm.DB

func init(){
    // We set up the database
    var err error

    dbConfig := config.Config.DB

    switch dbConfig.Adapter {
    case "mysql":
            DBCon, err = gorm.Open("mysql", fmt.Sprintf("%v:%v@tcp(%v:%v)/%v?charset=utf8&parseTime=True&loc=Local", dbConfig.User, dbConfig.Password, dbConfig.Host, dbConfig.Port, dbConfig.Name))
    case  "postgres":
            DBCon, err = gorm.Open("postgres", fmt.Sprintf("user=%v password=%v host=%v port=%v dbname=%v sslmode=disable", dbConfig.User, dbConfig.Password, dbConfig.Host, dbConfig.Port, dbConfig.Name))
    case "mssql":
            DBCon, err = gorm.Open("mssql", fmt.Sprintf("sqlserver://%v:%v@%v:%v?database=%v", "%v:%v@tcp(%v:%v)/%v?charset=utf8&parseTime=True&loc=Local", dbConfig.User, dbConfig.Password, dbConfig.Host, dbConfig.Port, dbConfig.Name))
    default:
            panic("Database is not supported")
    }
    DBCon.DB().Ping()
    DBCon.DB().SetMaxIdleConns(10)
    DBCon.DB().SetMaxOpenConns(100)
    defer DBCon.Close()
    DBCon.LogMode(true) // SQL Logging

    // Stop running if there are problems connecting to database
    if err != nil {
      log.Fatal("%s - cannot connect to database", err)
    }
}
