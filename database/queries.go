package database

import (
	"strings"

	"gorm.io/gorm"
)

// IsValidRecipient checks if a mask address exists using SELECT EXISTS
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

// GetMask checks if a mask exists in the database and returns a subset of the record if that is the case
func GetMask(db *gorm.DB, mask string) (*maskRecord, error) {
	record := &maskRecord{}
	err := db.Table("masks").Select("masks.mask, masks.enabled, emails.email").Joins("inner join emails on emails.id = masks.forward_to").Where("masks.mask = ?", mask).First(&record).Error
	return record, err
}

// GetValidRecipients validates a slice of email addresses by checking if they exist in the masks table
type Recipient struct {
	Mask  string
	Email string
}

func GetValidRecipients(db *gorm.DB, to []string) []Recipient {
	recipients := make([]Recipient, 0)
	for _, v := range to {
		v = strings.ToLower(v)
		//TODO: support more domains in the future
		if strings.Split(v, "@")[1] == "relay.maskr.app" {
			result, err := GetMask(db, v)
			if err == nil {
				if result.Enabled {
					recipients = append(recipients, Recipient{result.Mask, result.Email})
				}
			}
		}
	}
	return recipients
}

// IncrementReceivedCount increments the value of the `messages_received` column in a mask record
func IncrementReceivedCount(db *gorm.DB, mask string) error {
	return db.Table("masks").Where("mask = ?", mask).UpdateColumn("messages_received", gorm.Expr("messages_received + ?", 1)).Error
}

// IncrementForwardedCount increments both the value of the `messages_forwarded` AND `messages_received` column in a mask record
func IncrementForwardedCount(db *gorm.DB, mask string) error {
	//TODO: support slice as input
	return db.Table("masks").Where("mask = ?", mask).Updates(map[string]interface{}{"messages_received": gorm.Expr("messages_received + ?", 1), "messages_forwarded": gorm.Expr("messages_forwarded + ?", 1)}).Error
}
