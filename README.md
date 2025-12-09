# rargo

Простой архиватор RAR 5.0 в режиме store.

## Особенности

- Создаёт архивы RAR 5.0 без сжатия (режим store).
- Поддерживает файлы и директории.
- Шифрование файлов с паролем (AES-256 CBC с PBKDF2).
- Совместим с unrar 5.x и 6.x.
- Интерфейс командной строки.

## Установка

```bash
go build -o rargo .
```

## Использование

```bash
./rargo a archive.rar file1.txt directory/ [--verbose] [--password PASS]
```

- `a`: Команда добавления.
- `archive.rar`: Выходной файл архива.
- `file1.txt directory/`: Файлы и директории для архивации.
- `--verbose`: Выводить прогресс.
- `--password PASS`: Пароль для шифрования файлов.

## Пример

```bash
echo "Hello World" > test.txt
mkdir testdir
echo "File in dir" > testdir/file.txt
./rargo a archive.rar test.txt testdir --verbose --password mypass
unrar x archive.rar
# При распаковке unrar запросит пароль
```

## Производительность

- Использует буферизованный I/O для эффективной записи.
- Минимальное использование памяти для небольших файлов.
- Для больших файлов добавлена потоковая обработка и concurrency.
- Шифрование использует PBKDF2 с 524288 итерациями для безопасности.

## Лицензия

MIT
