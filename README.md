# CLI-утилита на Go для шифрования/расшифрования файлов с AES-128 (ECB, CBC, CFB, OFB, CTR) и генерацией криптостойких ключей/IV.

## Сборка
```
go build -o bin/cryptocore ./cmd/cryptocore
```

## Зависимости

- Go 1.21+
- OpenSSL (для interoperability‑тестов)
- NIST STS (для тестов случайности)

## Структура проекта
```
cmd/cryptocore/ main.go # входная точка, CLI
internal/cli/ options.go # парсинг и валидация флагов
internal/crypto/ *.go # AES-128 ECB/CBC/CFB/OFB/CTR, PKCS#7, IV
internal/fs/ fileio.go # файловый ввод/вывод
go.mod
```
## Использование

cryptocore <args>               # Encryption/Decryption
cryptocore dgst ...             # Hashing
cryptocore hmac ...             # HMAC

### Шифрование (с генерацией ключа)

Если `--key` не указан, ключ генерируется автоматически и выводится в stdout.
```
bin/cryptocore --algorithm aes --mode cbc --encrypt
--input plain.txt --output cbc_cipher.bin
```
Вывод: `[INFO] Generated random key: <ключ>`

### Расшифрование (ключ обязателен)
```
bin/cryptocore --algorithm aes --mode cbc --decrypt
--key <ключ_из_stdout>
--input cbc_cipher.bin --output plain.txt
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
### Uniqueness Test

Проверка уникальности 1000 сгенерированных ключей.
```
go run ./cmd/test-uniqueness/main.go
```

### NIST Statistical Test Suite

1.  **Сгенерировать данные для теста:**

    ```
    go run ./cmd/generate-nist-data/main.go
    ```
    Это создаст файл `nist_test_data.bin` размером 10 МБ.

2.  **Запустить NIST STS:**
    - Скачайте и соберите [NIST STS](https://csrc.nist.gov/projects/random-bit-generation/documentation-and-software).
    - Запустите `assess` и в интерактивном режиме укажите файл `nist_test_data.bin`.

    ```
    # (из папки с NIST STS)
    ./assess 10000000
    ```

```

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
## Хеширование (dgst)
Поддержка алгоритмов SHA-256 (собственная реализация) и SHA-512.

### Использование
```
bin/cryptocore dgst --algorithm <sha256|sha512> --input <файл>
bin/cryptocore dgst --algorithm sha256 --input plain.txt
# Вывод: <hash>  plain.txt
```
HMAC (hmac)
Вычисление кодов аутентификации сообщений (HMAC) на базе SHA-256 и SHA-512.

Использование
```
bin/cryptocore hmac --algorithm <sha256|sha512> --key <ключ> --input <файл>

bin/cryptocore hmac --algorithm sha256 --key 0b0b0b0b --input data.txt
# Вывод: <hmac_hash>  data.txt
```

