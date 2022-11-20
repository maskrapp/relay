package database

import (
	"strings"

	"gorm.io/gorm"
)

func IsValidRecipient(db *gorm.DB, to string) bool {
	to = strings.ToLower(to)
	split := strings.Split(to, "@")
	if len(split) != 2 {
		return false
	}
	if split[1] != "relay.maskr.app" {
		return false
	}

	var result struct {
		Found bool
	}
	db.Raw("SELECT EXISTS(SELECT 1 FROM masks WHERE mask = ?) AS found",
		to).Scan(&result)
	return result.Found
}

type maskRecord struct {
	Mask    string `json:"mask"`
	Email   string `json:"email"`
	Enabled bool   `json:"enabled"`
}

func GetMask(db *gorm.DB, mask string) (*maskRecord, error) {
	record := &maskRecord{}
	err := db.Table("masks").Select("masks.mask, masks.enabled, emails.email").Joins("inner join emails on emails.id = masks.forward_to").Where("masks.mask = ?", mask).First(&record).Error
	return record, err
}

func GetValidRecipients(db *gorm.DB, to []string) []string {
	recipients := make([]string, 0)
	for _, v := range to {
		v = strings.ToLower(v)
		//TODO: support more domains in the future
		if strings.Split(v, "@")[1] == "relay.maskr.app" {
			result, err := GetMask(db, v)
			if err == nil {
				if result.Enabled {
					recipients = append(recipients, result.Email)
				}
			}
		}
	}
	return recipients
}
