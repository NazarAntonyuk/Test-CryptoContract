package main

import (
	"crypto/x509"
	"fmt"
	"go.mozilla.org/pkcs7"
	"log"
	"os"
	"os/exec"
)

func main() {
	privateKeyPath := "private_key.pem"         // Шлях до файлу з приватним ключем
	publicKeyPath := "public_key.pem"           // Шлях до файлу з публічним ключем
	certificatePath := "certificate.crt"        // Шлях до файлу з сертифікатом
	contractPath := "contract.py"               // Шлях до файлу з контрактом
	signedContractPath := "signed_contract.p7s" // Шлях до файлу для збереження підписаного контракту

	// Зчитуємо вміст файлів з ключами, сертифікатом та контрактом
	privateKey, err := os.ReadFile(privateKeyPath)
	if err != nil {
		log.Fatalf("Помилка при читанні приватного ключа: %s", err)
	}

	publicKey, err := os.ReadFile(publicKeyPath)
	if err != nil {
		log.Fatalf("Помилка при читанні публічного ключа: %s", err)
	}

	certificate, err := os.ReadFile(certificatePath)
	if err != nil {
		log.Fatalf("Помилка при читанні сертифікату: %s", err)
	}

	contractContent, err := os.ReadFile(contractPath)
	if err != nil {
		log.Fatalf("Помилка при читанні контракту: %s", err)
	}

	// Підписуємо контракт
	signedContract, err := signContract(contractContent, privateKey, publicKey, certificate)
	if err != nil {
		log.Fatalf("Помилка при підписі контракту: %s", err)
	}

	// Перевіряємо підпис контракту
	err = verifySignature(signedContract, certificate)
	if err != nil {
		fmt.Println("Перевірка підпису неуспішна")
	} else {
		fmt.Println("Перевірка підпису успішна")

		// Розшифровуємо контракт
		decryptedContract, err := decryptContract(signedContract, publicKey)
		if err != nil {
			log.Fatalf("Помилка при розшифруванні контракту: %s", err)
		}

		// Виконуємо контракт
		err = executeContract(decryptedContract)
		if err != nil {
			log.Fatalf("Помилка при виконанні контракту: %s", err)
		}

		// Зберігаємо підписаний контракт
		err = saveSignedContract(signedContract, signedContractPath)
		if err != nil {
			log.Fatalf("Помилка при збереженні підписаного контракту: %s", err)
		}
	}
}

// signContract підписує контракт за допомогою приватного ключа та сертифікату
func signContract(contract []byte, privateKey []byte, publicKey []byte, certificate []byte) ([]byte, error) {
	// Розбиваємо сертифікат з PEM-формату на об'єкт *x509.Certificate
	cert, err := x509.ParseCertificate(certificate)
	if err != nil {
		return nil, err
	}

	// Розбиваємо приватний ключ з PEM-формату на об'єкт *ecdsa.PrivateKey
	key, err := x509.ParseECPrivateKey(privateKey)
	if err != nil {
		return nil, err
	}

	// Створюємо об'єкт PKCS#7 для підпису контракту
	p7, err := pkcs7.NewSignedData(contract)
	if err != nil {
		return nil, err
	}

	// Додаємо приватний ключ, сертифікат та конфігурацію до об'єкту PKCS#7
	err = p7.AddSigner(cert, key, pkcs7.SignerInfoConfig{})
	if err != nil {
		return nil, err
	}

	// Підписуємо контракт
	signedData, err := p7.Finish()
	if err != nil {
		return nil, err
	}

	return signedData, nil
}

// verifySignature перевіряє підпис контракту за допомогою сертифікату
func verifySignature(signedContract []byte, certificate []byte) error {
	// Розбиваємо підписаний контракт на об'єкт PKCS#7 для перевірки
	p7, err := pkcs7.Parse(signedContract)
	if err != nil {
		return err
	}

	// Перевіряємо підпис
	err = p7.Verify()
	if err != nil {
		return err
	}

	return nil
}

// decryptContract розшифровує підписаний контракт за допомогою публічного ключа
func decryptContract(signedContract []byte, publicKey []byte) ([]byte, error) {
	// Розбиваємо публічний ключ з PEM-формату на об'єкт *x509.Certificate
	cert, err := x509.ParseCertificate(publicKey)
	if err != nil {
		return nil, err
	}

	// Розбиваємо підписаний контракт на об'єкт PKCS#7 для розшифрування
	p7, err := pkcs7.Parse(signedContract)
	if err != nil {
		return nil, err
	}

	// Розшифровуємо контракт за допомогою публічного ключа
	decryptedData, err := p7.Decrypt(cert, nil)
	if err != nil {
		return nil, err
	}

	return decryptedData, nil
}

// executeContract виконує контракт, передаючи його як код пайтонівської програми
func executeContract(contract []byte) error {
	// Запускаємо пайтонівську програму з розшифрованим контрактом
	cmd := exec.Command("python3", "-c", string(contract))
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	err := cmd.Run()
	if err != nil {
		return err
	}

	return nil
}

// saveSignedContract зберігає підписаний контракт у файл
func saveSignedContract(signedContract []byte, filePath string) error {
	file, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = file.Write(signedContract)
	if err != nil {
		return err
	}

	return nil
}
