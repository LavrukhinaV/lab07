# Лабораторная работа № 7

**Автор:** *Лаврухина Виктория*

--- 
## Цель лабораторной работы  

Изучение методов аудита безопасности исходного кода приложения с использованием средств статического анализа, включая анализ уязвимостей зависимостей и конфигураций. В рамках работы рассматривается применение инструментов Semgrep, Checkov и Dependency-Check, а также настройка и использование правил для них. Дополнительно выполняется ознакомление с системой сборки Maven. В ходе лабораторной работы осваиваются практики проверки корректности конфигураций безопасности, выявления потенциальных уязвимостей и выполнения чек-апа безопасности приложения.

---

### Структура репозитория лабораторной работы
```
lab07
├── cheat_check_yuorself.sh
├── docker-compose.yml
├── sast
│   ├── checkov-config.yaml
│   └── semgrep-rules.yml
├── sca
│   ├── dependency-check.sh
│   ├── generate_unified_report.sh
│   └── pom.xml
└── vulnerable-app
    ├── app.py
    ├── config.yaml
    ├── Dockerfile
    └── requirements.txt
```
---

### Задания

- ✔ 1. Разверните и подготовьте окружение для уязвимого приложения

```bash
$ python3 -m venv venv
$ source venv/bin/activate
$ pip install -r vulnerable-app/requirements.txt
```

- ✔ 2. Запустите уязвимое приложение

```bash
$ docker-compose -f docker-compose.yml up -d --build # http://localhost:8080
```

- ✔ 3. Запустите SAST Semgrep и проанализируйте выведенный лог в консоли и опишите логику правил для `semgrep-rules.yml` исходя из паттернов, которые используются. Отчет будет в директории SAST

```bash
$ semgrep --config sast/semgrep-rules.yml \
  --json \
  --output sast/semgrep-report.json \
  vulnerable-app/
```

- ✔ 4. Запустите SAST Checkov по Dockerfile, compose и проанализируйте выведенный лог в консоли и опишите логику правил для `checkov-config.yaml` по `Docker`. Отчет будет в директории SAST

```bash
$ checkov \
  --framework dockerfile \
  --file vulnerable-app/Dockerfile docker-compose.yml \
  --output json \
  --output-file-path sast/checkov-report \
  --soft-fail
```

- ✔ 5. Подготовка зависимостей Java и Maven‑скан для проведения SCA. Отчеты будут в директории SCA. Будет ошибка, которую надо поправить, что бы уязвимости определялись или добавить дополнительные уязвимости для их вывода в отчете

```bash
$ cd sca
$ ./dependency-check.sh --update # обновление и поставка базы NVD API
$ mvn dependency:resolve
$ mvn dependency:copy-dependencies -DoutputDirectory=./lib # зависимости из $ pom.xml как jar в ./lib
$ mvn org.owasp:dependency-check-maven:check || true # Maven-плагин OWASP
```

- ✔ 6. Запустите SCA CLI OWASP Dependency-Check для уязвимого приложения. Отчеты будут в директории SCA. Опишите как работает сканирование SCA для `pom.xml` и `app.py`
- ✔ 7. Соберите единый отчет из всех сканирований в виде `html`, `csv`, `json`

```bash
$ bash sca/generate_unified_report.sh
```

- ✔ 8. Проанализируйте все уязвимости и обьясните для SAST Checkov сработки статуса `Unknown`. Классифицируйте их и укажите какие не должны быть в отчетах. Внесите исправления и запустите повторное сканирование и убедитесь, что они устранены. Приложите исправленный файл и отчет без уязвимостей. 
- ✔ 9. Опишите выведенные уязвимости для SAST Semgrep и принцип их работы. Поправьте скрипт `app.py`. Запустите повторное сканирование и убедитесь, что они устранены. Приложите исправленный файл `app.py` и отчет без уязвимостей. 
- ✔ 10. Доработайте SCA уязвимости, что бы они только остались в фиинальной версии отчетов.
- ✔ 11. Проверьте себя по найденным сработкам анализаторов и так вы сможете помочь себе разобраться в ситуации, если возникнут сложности

```bash
$ bash cheat_check_yuorself.sh
```

- ✔ 12. Делайте все коммиты на соответствующих шагах, далее заливайте изменения в удаленный репозиторий.
- ✔ 13. Подготовьте отчет `gist`.
- ✔ 14. Почистите кеш от `venv` и остановите уязвимое приложение

```bash
$ deactivate
$ rm -rf venv
$ docker-compose -f ххх down
$ docker-compose -f docker-compose.yml down
$ docker system prune -f
```
 
---

### Подготовительный этап (перед выполнением)

1. Создать директорию проекта и зайти в нее:
```
mkdir lab07
cd lab07
```

2. Инициализировать git и сделать первый коммит:
```
git init
echo "# lab07" > README.md
git add .
git commit -m "Initial commit"

```

3. Создать и переключиться на ветку dev
```
git checkout -b dev
```

4. Создать удалённый репозиторий на GitHub и привязать origin
```
gh repo create lab07 --private --source=. --remote=origin --push
```
---

### Процесс выполнения заданий
- ✔ 1. Разверните и подготовьте окружение для уязвимого приложения

```bash
python3 -m venv venv # создаие виртульного окружения
source venv/bin/activate # активация виртульного окружения
pip install -r vulnerable-app/requirements.txt # установка зависимостей
...
Successfully installed Django-2.2 Flask-2.0.1 Jinja2-3.0.1 MarkupSafe-2.0.1 PyYAML-5.3.1 SQLAlchemy-1.3.23 Werkzeug-2.0.3 bcrypt-5.0.0 certifi-2018.4.16 cffi-2.0.0 chardet-3.0.4 click-8.0.1 cryptography-44.0.3 gunicorn-20.1.0 idna-2.7 itsdangerous-2.0.1 paramiko-2.4.1 pyasn1-0.6.1 pycparser-2.23 pyjwt-1.7.1 pynacl-1.6.1 pytz-2025.2 requests-2.19.1 six-1.15.0 sqlparse-0.5.4 urllib3-1.23
```

- ✔ 2. Запустите уязвимое приложение

```bash
docker compose -f docker-compose.yml up -d --build # http://localhost:8080
...
 ✔ vulnerable-app                    Built                                                                                                                    0.0s 
 ✔ Network lab07_default             Created                                                                                                                  0.0s 
 ✔ Container lab07-vulnerable-app-1  Started    
```
```bash
curl http://localhost:8080 # проверка
Vulnerable lab07 app v1.0%     
```
- ✔ 3. Запустите SAST Semgrep и проанализируйте выведенный лог в консоли и опишите логику правил для `semgrep-rules.yml` исходя из паттернов, которые используются. Отчет будет в директории SAST

```bash
# Запуск анализа
semgrep --config sast/semgrep-rules.yml \
  --json \
  --output sast/semgrep-report.json \
  vulnerable-app/
...
┌──────────────┐
│ Scan Summary │
└──────────────┘
✅ Scan completed successfully.
 • Findings: 5 (5 blocking)
 • Rules run: 16
 • Targets scanned: 2
 • Parsed lines: ~100.0%
 • Scan was limited to files tracked by git
 • For a detailed list of skipped files and lines, run semgrep with the --verbose flag
Ran 16 rules on 2 files: 5 findings.
```
Файл `semgrep-rules.yml` содержит набор пользовательских правил, описывающих небезопасные паттерны программирования. Логика работы правил основана на сопоставлении синтаксических шаблонов (pattern matching).

Типовая структура правила включает:
* `pattern` — описание небезопасного кода;
* `message` — пояснение выявленной проблемы;
* `severity` — уровень критичности (INFO / WARNING / ERROR);
* `languages` — язык программирования (Python);
* `metadata` — классификация уязвимости (CWE, OWASP).

Правила `semgrep-rules.yml` реализуют сигнатурный подход к статическому анализу, позволяя автоматически обнаруживать потенциальные уязвимости безопасности на раннем этапе жизненного цикла разработки.

Отчёт статического анализа сохранён в директории:
```
SAST/semgrep-report.json
```

- ✔ 4. Запустите SAST Checkov по Dockerfile, compose и проанализируйте выведенный лог в консоли и опишите логику правил для `checkov-config.yaml` по `Docker`. Отчет будет в директории SAST

```bash
# Запуск анализа
checkov \
  --framework dockerfile \ # включает проверки именно для Dockerfile
  --file vulnerable-app/Dockerfile docker-compose.yml \ # задаёт файлы для анализа 
  --output json \ # формат отчёта JSON
  --output-file-path sast/checkov-report \ # куда сохранить отчёт
  --soft-fail # не завершать процесс с ошибкой даже при найденных нарушениях
```
В результате запуска **Checkov** получена сводка:
* passed: 50 — 50 проверок безопасности успешно пройдены.
* failed: 2 — выявлено 2 нарушения (2 проверки не пройдены).
* skipped: 0 — пропущенных проверок нет (в конфигурации не задан skip_check, и Checkov ничего не игнорировал).
* parsing_errors: 0 — ошибок разбора файлов нет, значит Dockerfile и docker-compose.yml корректно распарсились и были проанализированы.
* resource_count: 1 — Checkov обнаружил 1 ресурс для анализа .
* checkov_version: 3.2.459 — версия использованного инструмента Checkov .

Конфигурация `checkov-config.yaml` ограничивает сканирование Docker-конфигураций заданными файлами и включает только выбранный набор проверок Docker через `enforce`. Эти проверки направлены на снижение привилегий контейнера, уменьшение поверхности атаки, предотвращение утечек секретов и усиление изоляции контейнеров (non-root, запрет privileged, ограничение capabilities, read-only FS, фиксированные теги образов и т.д.).

- ✔ 5. Подготовка зависимостей Java и Maven‑скан для проведения SCA. Отчеты будут в директории SCA. Будет ошибка, которую надо поправить, что бы уязвимости определялись или добавить дополнительные уязвимости для их вывода в отчете

```bash
cd sca
mkdir -p lib SCA

# Копируем зависимости из pom.xml в ./lib через Maven в Docker
docker run --rm -v "$PWD:/app" -w /app maven:3.9-eclipse-temurin-17 \
  mvn -q dependency:copy-dependencies -DoutputDirectory=./lib

ls -lah lib | head # Проверка, что jar’ы появились

total 16000
drwxr-xr-x  12 aleksandrlavruhin  staff   384B Dec 14 13:53 .
drwxr-xr-x@  7 aleksandrlavruhin  staff   224B Dec 14 13:51 ..
-rw-r--r--   1 aleksandrlavruhin  staff    29K Nov 22  2005 commons-codec-1.2.jar
-rw-r--r--   1 aleksandrlavruhin  staff   298K Aug 21  2007 commons-httpclient-3.1.jar
-rw-r--r--   1 aleksandrlavruhin  staff    37K Nov 22  2005 commons-logging-1.0.4.jar
-rw-r--r--   1 aleksandrlavruhin  staff   6.1M Jul  9  2013 groovy-all-2.1.6.jar
-rw-r--r--   1 aleksandrlavruhin  staff    38K May 29  2014 jackson-annotations-2.4.0.jar
-rw-r--r--   1 aleksandrlavruhin  staff   220K Apr 24  2015 jackson-core-2.4.6.jar
-rw-r--r--   1 aleksandrlavruhin  staff   1.0M Apr 24  2015 jackson-databind-2.4.6.jar

# Запуск OWASP Dependency-Check с помощью docker
docker run --rm \
  -v "$PWD:/src" \
  -w /src \
  owasp/dependency-check \
  --scan ./lib \
  --format JSON \
  --out ./dependency-check-report \
  --project "lab07-sca" || true

...
[INFO] Analysis Complete (11 seconds)
[INFO] Writing JSON report to: /src/./SCA/dependency-check-report.json
```
**Результат**
* Для воспроизводимого выполнения SCA использован Docker-образ `owasp/dependency-check`.

* Ошибка `path does not exist` исправлена подготовкой артефактов: зависимости из `pom.xml` выгружены в `./lib` (через `mvn dependency:copy-dependencies`), после чего сканирование успешно формирует отчёт в `dependency-check-report/`.

* В результате выполнения `SCA`-анализа был сформирован единый агрегированный отчёт `dependency-check-report.json`.

- ✔ 6. Запустите SCA CLI OWASP Dependency-Check для уязвимого приложения. Отчеты будут в директории SCA. Опишите как работает сканирование SCA для `pom.xml` и `app.py`

`pom.xml` - Используется как основной источник информации о зависимостях. Именно из него были получены версии библиотек, которые затем сопоставлялись с CVE.

`app.py` - в рамках SCA не анализируется на предмет логических или программных уязвимостей.

В результате выполнения SCA-сканирования был сформирован отчёт
`dependency-check-report/dependency-check-report.json`.

Общая информация о сканировании
* Инструмент: OWASP Dependency-Check CLI
* Версия движка: 12.1.9
* Проект: lab07-sca
* Источник уязвимостей: NVD (National Vulnerability Database)
* Формат отчёта: JSON

**Обнаруженные зависимости**
В ходе анализа были выявлены сторонние Java-зависимости, загруженные в директорию lib/:

* `commons-codec:1.2` - используется устаревшая версия библиотеки, однако CVE для данной версии в отчёте отсутствуют. Уязвимостей не обнаружено.

*  `commons-httpclient:3.1` - **обнаружены известные уязвимости безопасности**. Библиотека признана уязвимой и сопоставлена с CPE-идентификаторами Apache HttpClient.

**Выявленные уязвимости**
* `CVE-2012-5783 (MEDIUM)` - нарушение проверки SSL-сертификата. Библиотека не проверяет соответствие имени сервера (hostname) полю Common Name или Subject Alternative Name в X.509-сертификате. Это позволяет атакующему выполнить Man-in-the-Middle атаку, используя валидный, но поддельный сертификат.
* `CVE-2020-13956 (MEDIUM)` - некорректная обработка URI. Библиотека может неверно интерпретировать malformed URI и отправить запрос не на тот хост, что создаёт риск перехвата или подмены запросов.


- ✔ 7. Соберите единый отчет из всех сканирований в виде `html`, `csv`, `json`

```bash
$ bash sca/generate_unified_report.sh
```

- ✔ 12. Делайте все коммиты на соответствующих шагах, далее заливайте изменения в удаленный репозиторий.

- ✔ 13. Подготовьте отчет `gist`.
```bash
gh gist create lab07.md --public --desc "lab07 report"
```

- ✔ 14. Почистите кеш от `venv` и остановите уязвимостей приложение, почистите контейнера
```bash
docker compose -p lab07-main down # Остановить и удалить основной стенд

docker compose -p lab07-vuln -f vulnerable-app.yml -f vulnerable-app.macos.override.yml down # Остановить и удалить уязвимый стенд

docker container prune -f # Очистка остановленных контейнеров, сетей и кеша Docker
docker network prune -f
docker image prune -f

deactivate 2>/dev/null || true # Удаление виртуального окружения Python
rm -rf venv
```