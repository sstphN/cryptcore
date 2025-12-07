# CLI‑утилита на Go для шифрования и расшифрования файлов с помощью AES‑128 в режимах ECB, CBC, CFB, OFB и CTR.

## Сборка
```
go build -o bin/cryptocore ./cmd/cryptocore
```

## Зависимости

- Go 1.21+
- OpenSSL (для interoperability‑тестов)

## Структура проекта
```
cmd/cryptocore/ main.go # входная точка, CLI
internal/cli/ options.go # парсинг и валидация флагов
internal/crypto/ *.go # AES-128 ECB/CBC/CFB/OFB/CTR, PKCS#7, IV
internal/fs/ fileio.go # файловый ввод/вывод
go.mod
```
## Использование
```
bin/cryptocore
--algorithm aes
--mode <ecb|cbc|cfb|ofb|ctr>
--encrypt|--decrypt
--key <32-hex-символа>
--input <входной_файл>
[--output <выходной_файл>]
[--iv <32-hex-символа>]
```
## Пример
```
KEY=000102030405060708090a0b0c0d0e0f

bin/cryptocore --algorithm aes --mode cbc --encrypt
--key $KEY --input plain.txt --output cbc_cipher.bin

bin/cryptocore --algorithm aes --mode cbc --decrypt
--key $KEY --input cbc_cipher.bin --output cbc_plain.txt
```

## Тесты
### Round‑trip
```
echo 'test message 123' > plain.txt
KEY=000102030405060708090a0b0c0d0e0f

for MODE in ecb cbc cfb ofb ctr; do
bin/cryptocore --algorithm aes --mode $MODE --encrypt
--key $KEY --input plain.txt --output ${MODE}_cipher.bin

bin/cryptocore --algorithm aes --mode $MODE --decrypt
--key $KEY --input ${MODE}_cipher.bin --output ${MODE}_plain.txt

echo "mode=$MODE"; diff plain.txt ${MODE}_plain.txt || echo "MISMATCH in $MODE"
done
```
### Interoperability с OpenSSL
ECB:
```
KEY=000102030405060708090a0b0c0d0e0f

openssl enc -aes-128-ecb -K $KEY
-in plain.txt -out openssl_ecb.bin

bin/cryptocore --algorithm aes --mode ecb --decrypt
--key $KEY --input openssl_ecb.bin --output from_openssl_ecb.txt
```
CBC:
```
bin/cryptocore --algorithm aes --mode cbc --encrypt
--key $KEY --input plain.txt --output cbc_cipher.bin

dd if=cbc_cipher.bin of=iv.bin bs=16 count=1 status=none
dd if=cbc_cipher.bin of=cbc_cipher_only.bin bs=16 skip=1 status=none
IV_HEX=$(xxd -p iv.bin | tr -d '\n')

openssl enc -aes-128-cbc -d -K $KEY -iv $IV_HEX
-in cbc_cipher_only.bin -out from_cryptocore_cbc.txt
```
