# Лабораторная работа № 7

**Автор:** *Лаврухина Виктория*

--- 
## Цель лабораторной работы  

Изучение методов аудита безопасности исходного кода приложения с использованием средств статического анализа, включая анализ уязвимостей зависимостей и конфигураций. В рамках работы рассматривается применение инструментов Semgrep, Checkov и Dependency-Check, а также настройка и использование правил для них. Дополнительно выполняется ознакомление с системой сборки Maven. В ходе лабораторной работы осваиваются практики проверки корректности конфигураций безопасности, выявления потенциальных уязвимостей и выполнения чек-апа безопасности приложения.

---

### Структура репозитория лабораторной работы
```
lab07/
├── vulnerable-app/
│   ├── app.py                     # Исправленный код приложения 
│   ├── Dockerfile                 # Исправленный Dockerfile
│   ├── requirements.txt
│   └── config.yaml
│
├── sast/
│   ├── semgrep-report.json        # Итоговый SAST-отчёт
│   └── checkov-report/
│       └── results_json.json      # Итоговый Checkov-отчёт
│
├── sca/
│   ├── pom.xml                    # Maven-зависимости
│   ├── dependency-check-report/
│   │   └── dependency-check-report.json  # SCA-отчёт
│   ├── dependency-check.sh
│   ├── generate_unified_report.sh
│   └── unify_reports.py
│
├── reports/
│   ├── unified-report.json        # Финальный объединённый отчёт
│   ├── unified-report.csv
│   └── unified-report.html
│
├── cheat_check_yuorself.sh        # Self-check скрипт
├── docker-compose.yml
├── .gitignore
├── README.md
├── lab07.md
└── venv/                          # локальное окружение (в .gitignore)
```
---
### Gist отчет
https://gist.github.com/LavrukhinaV/1f757155d7df99b50b544dacd84e2d60
