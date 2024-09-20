package encrypt

import (
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

func Hash(password string) (string, error) {

	if password == "" {
		return "", fmt.Errorf("password can't be empty")
	} else {
		pass, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)

		if err != nil {
			return "Could not generate password", err
		}

		hashedPassword := string(pass)

		return hashedPassword, nil
	}
}

func VerifyPassword(password, hash string) (bool, error) {

	if password == "" || hash == "" {
		return false, fmt.Errorf("password or hash can't be empty")
	} else {

		err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))

		if err != nil {
			if err == bcrypt.ErrMismatchedHashAndPassword {
				return false, fmt.Errorf("passwords don't match")
			}
			return false, err
		}

		return true, nil
	}
}
