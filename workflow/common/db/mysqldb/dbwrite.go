package mysqldb

import (
	"github.com/projectdiscovery/gologger"
	"gorm.io/gorm"
)

func WriteToTargets(db *gorm.DB, Targets Targets) error {
	if err := db.Create(&Targets).Error; err != nil {
		gologger.Error().Msg(err.Error())
		return err
	}
	return nil
}

func WriteToIPs(db *gorm.DB, IPs IPs) error {
	if err := db.Create(&IPs).Error; err != nil {
		gologger.Error().Msg(err.Error())
		return err
	}
	return nil
}

func WriteToDomains(db *gorm.DB, Domains Domains) error {
	if err := db.Create(&Domains).Error; err != nil {
		gologger.Error().Msg(err.Error())
		return err
	}
	return nil
}
