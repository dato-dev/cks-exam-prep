# Глава 17. Минимизация базового образа

> **Что дальше.** Открываем домен **Supply Chain Security (20%)**. Всё, что лежит в образе,
> - это потенциальные CVE и инструменты атакующего: shell, пакетный менеджер, curl,
> компиляторы. В этой главе научимся писать Dockerfile с минимальным footprint'ом: маленький
> базовый образ, multi-stage сборка, непривилегированный пользователь, закреплённые версии.
> Заодно разберём харденинг самого Docker-демона.

## 17.1. Почему размер образа - это безопасность

| Базовый образ | Размер (порядок) | Shell / пакетный менеджер | Типичное число CVE |
|---------------|------------------|---------------------------|--------------------|
| `ubuntu:24.04` | ~80 МБ | есть / apt | десятки |
| `debian:bookworm-slim` | ~75 МБ | есть / apt | десятки |
| `alpine:3.x` | ~8 МБ | есть (busybox) / apk | единицы |
| distroless (`gcr.io/distroless/static`) | ~2 МБ | нет / нет | около нуля |
| `scratch` | 0 | нет / нет | 0 (только ваш бинарник) |

Меньше пакетов - меньше уязвимостей, меньше инструментов для атакующего после
компрометации и быстрее сканирование и доставка.

## 17.2. Multi-stage сборка

Инструменты сборки (компилятор, исходники, dev-зависимости) не должны попадать в
финальный образ:

```dockerfile
# stage 1: сборка
FROM golang:1.24 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /app ./cmd/app

# stage 2: рантайм
FROM gcr.io/distroless/static:nonroot
COPY --from=build /app /app
USER nonroot:nonroot
ENTRYPOINT ["/app"]
```

## 17.3. Типичные ошибки в Dockerfile

```dockerfile
FROM ubuntu:latest                        # 1. плавающий тег
RUN apt-get update && apt-get install -y curl wget vim netcat   # 2. лишние пакеты
ENV DB_PASSWORD=supersecret               # 3. секрет в образе
COPY . /app                               # 4. копирование всего, включая .git и .env
RUN chmod 777 /app                        # 5. избыточные права
USER root                                 # 6. запуск от root
CMD ["/app/run.sh"]
```

Исправленный вариант:

```dockerfile
FROM ubuntu:24.04@sha256:<digest>         # 1. конкретная версия, лучше - digest
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/*           # 2. минимум пакетов, чистим кеш в том же слое
# 3. секреты - только в рантайме (Secret, внешнее хранилище), не в ENV/ARG
COPY app/ /app/                           # 4. только нужное + .dockerignore
RUN groupadd -r myuser && useradd -r -g myuser myuser \
 && chown -R myuser:myuser /app           # 5. права только нужному пользователю
USER myuser                               # 6. непривилегированный пользователь
CMD ["/app/run.sh"]
```

Правила:

- **Закрепляйте версию или digest** базового образа, никаких `latest`.
- **Каждый `RUN` - слой**: удаление файла в следующем слое не убирает его из образа.
  Секрет, добавленный и удалённый в разных слоях, остаётся в истории (`docker history`,
  распаковка слоёв).
- **`USER` в конце**, после всех действий, требующих root. Лучше - числовой UID
  (`USER 10001`), тогда `runAsNonRoot` в Kubernetes может его проверить.
- **Не ставьте** shell-утилиты «для отладки» в продакшн-образ - для этого есть
  `kubectl debug` с ephemeral-контейнером.
- **`.dockerignore`**: `.git`, `.env`, ключи, тесты.

## 17.4. Сборка и проверка

На экзамене собирают обычно `podman` или `docker`:

```bash
podman build -t cks:14 /var/work/14/
podman run --rm cks:14 id              # uid=1000(myuser) ...
podman history cks:14
podman image inspect cks:14 --format '{{.Config.User}}'
```

## 17.5. Харденинг Docker-демона

Если на ноде (или CI-агенте) используется Docker:

- **Сокет `/var/run/docker.sock`** = root на хосте. Права `root:docker 660`, в группе
  `docker` - никого лишнего; не монтируйте сокет в контейнеры.
- **Не публикуйте API демона по TCP** (`-H tcp://0.0.0.0:2375`) - это удалённый root без
  аутентификации. Если нужен удалённый доступ - только TLS (`2376` + `--tlsverify`).
- **`/etc/docker/daemon.json`**: `"userns-remap": "default"` (root в контейнере ≠ root на
  хосте), `"no-new-privileges": true`, `"icc": false`, `"live-restore": true`.
- **Проверяйте unit systemd**: флаги `-H` могут быть заданы в `ExecStart` или в drop-in
  `/etc/systemd/system/docker.service.d/`.

```bash
systemctl cat docker | grep ExecStart
ls -l /var/run/docker.sock
getent group docker
ss -tlpn | grep -E '2375|2376'
```

После правки: `systemctl daemon-reload && systemctl restart docker`.

## 17.6. Best practices

- **Минимальная база**: distroless или alpine; `scratch` для статических бинарников.
- **Multi-stage**: инструменты сборки не попадают в рантайм.
- **Версия/digest базового образа** закреплены.
- **Непривилегированный пользователь** (числовой UID).
- **Никаких секретов** в `ENV`, `ARG`, слоях; `.dockerignore`.
- **Регулярная пересборка** на обновлённой базе и сканирование (глава 20).
- **Docker-демон**: без TCP без TLS, минимальная группа docker, userns-remap.

## 17.7. Итоги главы

- Меньше образ - меньше CVE и инструментов атакующего.
- Multi-stage отделяет сборку от рантайма; distroless/scratch - минимальные базы.
- Типичные исправления Dockerfile: закреплённая версия, минимум пакетов, чистка кеша в том
  же слое, `USER` непривилегированный, без секретов.
- Удалённый в следующем слое файл остаётся в образе.
- Docker: сокет = root, TCP без TLS недопустим, userns-remap.

## 17.8. Вопросы для самопроверки

1. Почему удаление секрета отдельной инструкцией `RUN rm` не помогает?
2. Что даёт multi-stage сборка с точки зрения безопасности?
3. Почему лучше указывать числовой UID в `USER`?
4. Чем опасен `-H tcp://0.0.0.0:2375` у dockerd?
5. Как отлаживать под из distroless-образа без shell?

## Практика

Исправьте Dockerfile: версия базы, непривилегированный пользователь, сборка образа:

🧪 Лаба 19: [tasks/cks/labs/19](../../labs/19/README.MD)

Харденинг Docker-демона:

🧪 Лаба 29: [tasks/cks/labs/29](../../labs/29/README.MD)

---
[Оглавление](../README_RU.md) · [Глава 16](../16/ru.md) · [Глава 18](../18/ru.md)
