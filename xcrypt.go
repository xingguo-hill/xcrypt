package xcrypt

import (
	"crypto/sha256"
	"encoding/base64"

	"golang.org/x/crypto/bcrypt"
)

/**
 * @description:sha256 加密
 * @param {string} plaintext
 * @param {string} password
 * @return string ,error
 */
func Encrypt(plaintext string, saltkey string) (string, error) {
	key := generateKey(saltkey)
	encrypted := make([]byte, len(plaintext))
	for i := 0; i < len(plaintext); i++ {
		encrypted[i] = plaintext[i] ^ key[i%len(key)]
	}
	return base64.StdEncoding.EncodeToString(encrypted), nil
}

/**
 * @description:使用sha256 解密
 * @param {string} plaintext
 * @param {string} password
 * @return string ,error
 */
func Decrypt(ciphertext string, saltkey string) (string, error) {
	key := generateKey(saltkey)
	decodedCiphertext, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}

	decrypted := make([]byte, len(decodedCiphertext))
	for i := 0; i < len(decodedCiphertext); i++ {
		decrypted[i] = decodedCiphertext[i] ^ key[i%len(key)]
	}
	return string(decrypted), nil
}

/**
 * @description: bcrypt 生成hash密码
 * @param {string} password
 * @return string, error
 */
func HashPassword(password string) (string, error) {
	// 使用 bcrypt 生成密码哈希
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

/**
 * @description: bcrypt 生成hash密码与明文比对
 * @param {*} password
 * @param {string} hashedPassword
 * @return bool
 */
func CheckPassword(password, hashedPassword string) bool {
	// 验证密码与哈希是否匹配
	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	return err == nil
}

/**
 * @description:生成 32位Sum256
 * @param {string} password
 * @return [32]byte
 */
func generateKey(password string) [32]byte {
	return sha256.Sum256([]byte(password))
}

