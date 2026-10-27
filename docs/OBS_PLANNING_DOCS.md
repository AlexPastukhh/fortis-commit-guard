# Первый security-контракт obs-planning-docs

Источник параметров: profiles/obs-planning-docs.json; реестр: registry.json.
Security-профиль является предварительным и должен развиваться по RULE_AUTHORING.md.

| Область | Применяемый контракт |
| --- | --- |
| planning/ и -Planning/ вне выделенных программ | Пассивные Markdown/TXT; примеры кода допускаются как текст |
| Helper src и generated userscript | Профиль JS, границы импортов, ограничение прямых API и заявленных разрешений |
| Helper package.json | Утверждённая идентичность и точные build/test scripts; новые зависимости запрещены |
| Build/verify, workflow и управляющие файлы | Изменения требуют решения владельца |
| AI commands, templates и semantic seed | Изменения требуют смыслового рассмотрения владельцем |
| Существующие Java-инструменты, другие userscripts и TS-пример | Пока без собственного capability profile; изменение кода требует решения владельца |
| Код обычных тестов Helper | Изменение .mjs требует security-ревью до утверждения Node test capability profile |
| Наличие обычных тестов Helper | Удаление проверяется дополнительно при architecture=true |

Заморозка отдельных областей — временная security-граница при недостаточно описанных
возможностях. Она не является выводом, что изменение кода там обязательно вредоносно.

Разрешённые декларации userscript:

- match: https://chatgpt.com/* и https://chat.openai.com/*.
- grant: GM_getValue, GM_setValue, GM_xmlhttpRequest.
- connect: api.github.com.
- run-at: document-idle.

Это разрешённые возможности продукта, а не разрешение хранить настоящие credentials
в development Docker. Тестовые данные могут использовать фиктивные значения.

Профиль не доказывает, что любой запрос к разрешённому GitHub API имеет допустимое
содержимое. Внешние поведенческие тесты Save/export/conflict ещё предстоит реализовать.
