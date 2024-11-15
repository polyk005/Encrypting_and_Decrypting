package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/gob"
	"encoding/hex"
	"fmt"
	"io"
	"log"
)

type Person struct {
	Name string
	Age  int
}

func encrypt(keyString string, stringToEncrypt string) (encryptedString string) {
	key, _ := hex.DecodeString(keyString)
	plaintext := []byte(stringToEncrypt)

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}

	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)

	return base64.URLEncoding.EncodeToString(ciphertext)
}

func decrypt(keyString string, stringToDecrypt string) string {
	key, _ := hex.DecodeString(keyString)
	ciphertext, _ := base64.URLEncoding.DecodeString(stringToDecrypt)

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	if len(ciphertext) < aes.BlockSize {
		panic("ciphertext too short")
	}
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)

	stream.XORKeyStream(ciphertext, ciphertext)

	return fmt.Sprintf("%s", ciphertext)
}

func main() {
	var network bytes.Buffer
	enc := gob.NewEncoder(&network)

	err := enc.Encode(Person{"Harry Potter", 1000})
	if err != nil {
		log.Fatal("encode error:", err)
	}

	key := []byte("this's secret key.enough 32 bits")
	if _, err := rand.Read(key); err != nil {
		log.Fatal(err.Error())
	}
	keyStr := hex.EncodeToString(key)

	fmt.Println("Encrypting....")
	cryptoText := encrypt(keyStr, string(network.Bytes()))
	fmt.Println(cryptoText)
	if err != nil {
		log.Fatal("write file err: %v", err.Error())
	}

	fmt.Println("Decrypting.....")
	text := decrypt(keyStr, cryptoText)
	byteBuffer := bytes.NewBuffer([]byte(text))
	dec := gob.NewDecoder(byteBuffer)
	var person Person
	err = dec.Decode(&person)
	if err != nil {
		log.Fatal("decode error :", err)
	}
	fmt.Printf("%q: %d\n", person.Name, person.Age)
}

// func main() {
// 	originalText := "Hello GolinuxCloud members!"
// 	fmt.Println(originalText)

// 	key := []byte("this's secret key.enough 32 bits")
// 	if _, err := rand.Read(key); err != nil {
// 		panic(err.Error())
// 	}

// 	keyStr := hex.EncodeToString(key)

// 	fmt.Println("Encrypting...")
// 	cryptoText := encrypt(keyStr, originalText)
// 	fmt.Println(cryptoText)

// 	fmt.Println("Decrypting....")
// 	text := decrypt(keyStr, cryptoText)
// 	fmt.Println(text)
// }
