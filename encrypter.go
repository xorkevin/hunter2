package hunter2

type (
	// Encrypter is an encryption interface
	Encrypter interface {
		ID() string
		Encrypt(plaintext string) (string, error)
		Decrypt(ciphertext string) (string, error)
	}

	// Decrypter decrypts ciphertext
	Decrypter struct {
		ciphers map[string]Encrypter
	}
)
