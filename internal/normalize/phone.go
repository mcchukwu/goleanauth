package normalize

import (
	"strings"

	"github.com/nyaruka/phonenumbers"
)

// NigerianPhone normalizes Nigerian phone numbers to E.164 format.
func NigerianPhone(phone string) (string, error) {
	phone = strings.TrimSpace(phone)
	phone = strings.ReplaceAll(phone, " ", "")
	phone = strings.ReplaceAll(phone, "-", "")

	parsed, err := phonenumbers.Parse(phone, "NG")
	if err != nil {
		return "", err
	}

	phone = phonenumbers.Format(parsed, phonenumbers.E164)

	switch {
	case strings.HasPrefix(phone, "0"):
		return "+234" + phone[1:], nil
	case strings.HasPrefix(phone, "234"):
		return "+" + phone, nil
	default:
		return phone, nil
	}
}

// Phone normalizes any international phone number to E.164 format.
func Phone(phone, defaultRegion string) (string, error) {
	phone = strings.TrimSpace(phone)
	phone = strings.ReplaceAll(phone, " ", "")
	phone = strings.ReplaceAll(phone, "-", "")

	parsed, err := phonenumbers.Parse(phone, defaultRegion)
	if err != nil {
		return "", err
	}
	return phonenumbers.Format(parsed, phonenumbers.E164), nil
}
