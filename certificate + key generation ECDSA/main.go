package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"time"
)

const (
	privateKeyPath = "private_key.pem" // Шлях до файлу приватного ключа
	publicKeyPath  = "public_key.pem"  // Шлях до файлу публічного ключа
	certPath       = "certificate.crt" // Шлях до файлу сертифіката
)

func main() {
	// Генерація приватного ключа
	privateKey, err := generatePrivateKey()
	if err != nil {
		handleError("Не вдалося згенерувати приватний ключ:", err)
		return
	}
	savePrivateKey(privateKey)

	// Збереження публічного ключа
	publicKey := &privateKey.PublicKey
	savePublicKey(publicKey)

	// Створення та збереження самопідписаного сертифіката
	certificate, err := generateCertificate(privateKey, publicKey)
	if err != nil {
		handleError("Не вдалося створити сертифікат:", err)
		return
	}
	saveCertificate(certificate)

	fmt.Println("Операції завершено успішно.")
}

// generatePrivateKey генерує приватний ключ ECDSA
func generatePrivateKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

// savePrivateKey зберігає приватний ключ у файл
func savePrivateKey(privateKey *ecdsa.PrivateKey) {
	privateKeyFile, err := os.Create(privateKeyPath)
	if err != nil {
		handleError("Не вдалося створити файл приватного ключа:", err)
		return
	}
	defer privateKeyFile.Close()

	privateKeyBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		handleError("Не вдалося закодувати приватний ключ:", err)
		return
	}

	err = pem.Encode(privateKeyFile, &pem.Block{Type: "EC PRIVATE KEY", Bytes: privateKeyBytes})
	if err != nil {
		handleError("Не вдалося зберегти приватний ключ:", err)
		return
	}
	fmt.Println("Приватний ключ збережено у файлі", privateKeyPath)
}

// savePublicKey зберігає публічний ключ у файл
func savePublicKey(publicKey *ecdsa.PublicKey) {
	publicKeyFile, err := os.Create(publicKeyPath)
	if err != nil {
		handleError("Не вдалося створити файл публічного ключа:", err)
		return
	}
	defer publicKeyFile.Close()

	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		handleError("Не вдалося закодувати публічний ключ:", err)
		return
	}

	err = pem.Encode(publicKeyFile, &pem.Block{Type: "PUBLIC KEY", Bytes: publicKeyBytes})
	if err != nil {
		handleError("Не вдалося зберегти публічний ключ:", err)
		return
	}
	fmt.Println("Публічний ключ збережено у файлі", publicKeyPath)
}

// generateCertificate створює самопідписаний сертифікат
func generateCertificate(privateKey *ecdsa.PrivateKey, publicKey *ecdsa.PublicKey) ([]byte, error) {
	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	return x509.CreateCertificate(rand.Reader, &template, &template, publicKey, privateKey)
}

// saveCertificate зберігає сертифікат у файл
func saveCertificate(certificate []byte) {
	certFile, err := os.Create(certPath)
	if err != nil {
		handleError("Не вдалося створити файл сертифіката:", err)
		return
	}
	defer certFile.Close()

	err = pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: certificate})
	if err != nil {
		handleError("Не вдалося зберегти сертифікат:", err)
		return
	}
	fmt.Println("Сертифікат збережено у файлі", certPath)
}

// handleError обробляє помилки та виводить повідомлення про помилку
func handleError(message string, err error) {
	fmt.Println(message, err)
}
