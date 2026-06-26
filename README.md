# PassForge

Генератор надёжных паролей с анализом стойкости. Показывает энтропию, размер алфавита и время взлома брутфорсом.

## Возможности

- Генерация криптографически стойких паролей (`os.urandom`)
- Анализ энтропии и оценка стойкости
- Расчёт времени взлома (10 млрд попыток/сек)
- Настройка длины и набора символов
- Анализ существующих паролей
- Генерация нескольких паролей за раз

## Использование

```bash
# Сгенерировать пароль (по умолчанию 16 символов)
python3 passforge.py

# Длинный пароль
python3 passforge.py -l 32

# 5 паролей сразу
python3 passforge.py -n 5

# Только буквы и цифры (без спецсимволов)
python3 passforge.py --no-symbols

# Проанализировать существующий пароль
python3 passforge.py --analyze "MyP@ssw0rd123"
```

## Пример вывода

```
  Generated Password:
  ╔════════════════════╗
  ║  k7$Bm!xR2@pNq9F  ║
  ╚════════════════════╝

  Strength Analysis:
  ████████████████████  EXCELLENT

  Length             16 characters
  Entropy            94.8 bits
  Charset size       91 characters
  Combinations       ~10^31
  Crack time         ~10^12 years (10B guesses/s)

  Character types    abc  ABC  123  !@#
```

## Зависимости

Нет — чистый Python 3.10+.

## Лицензия

MIT
