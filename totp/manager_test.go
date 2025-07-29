package totp_test

import (
	"database/sql"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/theopenlane/iam/totp"
)

func TestDefaultName(t *testing.T) {
	userWithEmail := &totp.User{
		Email: sql.NullString{
			String: "jenny@example.com",
			Valid:  true,
		},
		Phone: sql.NullString{
			String: "5558675309",
			Valid:  true,
		},
	}

	userWithPhone := &totp.User{
		Email: sql.NullString{},
		Phone: sql.NullString{
			String: "5558675309",
			Valid:  true,
		},
	}

	// Test when email is not empty
	expectedName := "jenny@example.com"
	actualName := userWithEmail.DefaultName()
	assert.Equal(t, expectedName, actualName, "DefaultName() returned incorrect name")

	// Test when email is empty
	expectedName = "5558675309"
	actualName = userWithPhone.DefaultName()
	assert.Equal(t, expectedName, actualName, "DefaultName() returned incorrect name")
}
func TestDefaultOTPDelivery(t *testing.T) {
	userWithEmail := &totp.User{
		Email: sql.NullString{
			String: "jenny@example.com",
			Valid:  true,
		},
		Phone: sql.NullString{
			String: "5558675309",
			Valid:  true,
		},
	}

	userWithPhone := &totp.User{
		Email: sql.NullString{},
		Phone: sql.NullString{
			String: "5558675309",
			Valid:  true,
		},
	}

	expectedDeliveryWithEmail := totp.DeliveryMethod("email")
	actualDeliveryWithEmail := userWithEmail.DefaultOTPDelivery()
	assert.Equal(t, expectedDeliveryWithEmail, actualDeliveryWithEmail, "DefaultOTPDelivery() returned incorrect delivery method for user with email")

	expectedDeliveryWithPhone := totp.DeliveryMethod("phone")
	actualDeliveryWithPhone := userWithPhone.DefaultOTPDelivery()
	assert.Equal(t, expectedDeliveryWithPhone, actualDeliveryWithPhone, "DefaultOTPDelivery() returned incorrect delivery method for user with phone")
}
