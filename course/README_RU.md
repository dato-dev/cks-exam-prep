# Kubernetes Security: практический самоучитель для подготовки к CKS

Практический курс по безопасности Kubernetes с привязкой к лабораторным работам
(`tasks/cks/labs`) и мок-экзаменам (`tasks/cks/mock`). Для инженеров уровня CKA.
Главы 2-24 покрывают все шесть доменов экзамена **Certified Kubernetes Security Specialist
(CKS)** на Kubernetes v1.35, глава 25 - подготовка к самому экзамену.

Структура: каждая тема - папка с номером. Внутри лежат локализованные файлы. Основной язык -
русский (`ru.md`), с него делаются переводы.

- 🇷🇺 Русский - `ru.md` (основной, источник истины)

Каждая глава построена одинаково: теория с примерами → best practices → итоги → вопросы для
самопроверки → **Практика** со ссылкой на лабу или задачу мок-экзамена.

## Содержание

### Введение

1. [Модель угроз Kubernetes и карта экзамена CKS](01/ru.md)

### Домен 1. Cluster Setup (15%)

2. [NetworkPolicy: ограничиваем доступ на уровне кластера](02/ru.md)
3. [CIS Benchmark и безопасная конфигурация компонентов](03/ru.md)
4. [Ingress с TLS](04/ru.md)
5. [Защита метаданных нод и эндпоинтов](05/ru.md)
6. [Проверка бинарников платформы перед развёртыванием](06/ru.md)

### Домен 2. Cluster Hardening (15%)

7. [RBAC: минимизируем экспозицию](07/ru.md)
8. [ServiceAccount: осторожно с дефолтами](08/ru.md)
9. [Ограничение доступа к Kubernetes API](09/ru.md)
10. [Обновление Kubernetes для устранения уязвимостей](10/ru.md)

### Домен 3. System Hardening (10%)

11. [Харденинг ОС хоста, IAM и внешний сетевой доступ](11/ru.md)
12. [Харденинг ядра: AppArmor и seccomp](12/ru.md)

### Домен 4. Minimize Microservice Vulnerabilities (20%)

13. [Pod Security Standards и securityContext](13/ru.md)
14. [Управление секретами Kubernetes](14/ru.md)
15. [Изоляция: multi-tenancy и sandbox-контейнеры](15/ru.md)
16. [Шифрование трафика pod-to-pod: Cilium и Istio](16/ru.md)

### Домен 5. Supply Chain Security (20%)

17. [Минимизация базового образа](17/ru.md)
18. [Понимание supply chain: SBOM, CI/CD, реестры артефактов](18/ru.md)
19. [Защита supply chain: разрешённые реестры, подпись и проверка артефактов](19/ru.md)
20. [Статический анализ манифестов и образов](20/ru.md)

### Домен 6. Monitoring, Logging and Runtime Security (20%)

21. [Аудит-логи Kubernetes](21/ru.md)
22. [Поведенческий анализ в рантайме: Falco](22/ru.md)
23. [Обнаружение угроз и расследование атак](23/ru.md)
24. [Иммутабельность контейнеров в рантайме](24/ru.md)

### Подготовка к экзамену

25. [Экзамен CKS: формат, стратегия и чек-лист](25/ru.md)

## Покрытие программы экзамена

| Компетенция из программы CKS | Глава |
|------------------------------|-------|
| Use Network security policies to restrict cluster level access | 2 |
| Use CIS benchmark to review the security configuration of Kubernetes components | 3 |
| Properly set up Ingress with TLS | 4 |
| Protect node metadata and endpoints | 5 |
| Verify platform binaries before deploying | 6 |
| Use Role Based Access Controls to minimize exposure | 7 |
| Exercise caution in using service accounts | 8 |
| Restrict access to Kubernetes API | 9 |
| Upgrade Kubernetes to avoid vulnerabilities | 10 |
| Minimize host OS footprint | 11 |
| Using least-privilege identity and access management | 11 (+7, 8) |
| Minimize external access to the network | 11 (+5) |
| Appropriately use kernel hardening tools such as AppArmor, seccomp | 12 |
| Use appropriate pod security standards | 13 |
| Manage Kubernetes secrets | 14 |
| Understand and implement isolation techniques | 15 |
| Implement Pod-to-Pod encryption (Cilium, Istio) | 16 |
| Minimize base image footprint | 17 |
| Understand your supply chain (SBOM, CI/CD, artifact repositories) | 18 |
| Secure your supply chain (permitted registries, sign and validate artifacts) | 19 |
| Perform static analysis of user workloads and container images | 20 |
| Use Kubernetes audit logs to monitor access | 21 |
| Perform behavioral analytics to detect malicious activities | 22 |
| Detect threats within physical infrastructure, apps, networks, data, users and workloads | 23 |
| Investigate and identify phases of attack and bad actors within the environment | 23 |
| Ensure immutability of containers at runtime | 24 |
