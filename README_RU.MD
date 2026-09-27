# Certified Kubernetes Security Specialist (CKS) - учебные материалы

Полная подготовка к сертификации **Certified Kubernetes Security Specialist (CKS)**:
курс для самостоятельного изучения, практические лабы и полноценные мок-экзамены - всё в
одном месте.

## Что внутри

| Часть | Путь | Что это |
|-------|------|---------|
| **Курс** | [`course/`](course/README_RU.md) | 25 глав: от модели угроз до runtime-детекта, все домены экзамена |
| **Лабы** | [`labs/`](labs/) | практические лабы на реальных кластерах в AWS, привязаны к главам курса |
| **Мок-экзамены** | [`mock/`](mock/) | 4 мок-экзамена в формате CKS |

Рекомендуемый маршрут: изучить главу курса, закрепить её лабой, затем решать мок-экзамены на
время.

```bash
TASK=22 make run_cks_task      # развернуть лабу 22
TASK=22 make delete_cks_task   # удалить
TASK=01 make run_cks_mock      # развернуть мок-экзамен 01
TASK=01 make delete_cks_mock
```

## Лабы и главы курса

| Лаба | Тема | Глава |
|------|------|-------|
| 01 | kubectl contexts, сертификаты пользователей | 1, 7 |
| 02 | Falco, sysdig: лог событий в заданном формате | 22 |
| 03 | Доступ к kube-apiserver только через ClusterIP | 5, 9 |
| 04 | Pod Security Standard (enforce baseline) | 13 |
| 05 | CIS Benchmark (kube-bench) | 3 |
| 07 | OPA Gatekeeper: запрет реестра | 19 |
| 09 | AppArmor | 12 |
| 10 | Container Runtime Sandbox gVisor | 15 |
| 11 | Чтение Secret напрямую из etcd | 14 |
| 17 | Audit log | 21 |
| 19 | Исправление Dockerfile | 17 |
| 20 | Обновление кластера kubeadm | 10 |
| 21 | Сканирование образов (trivy) | 20 |
| 22 | NetworkPolicy | 2 |
| 23 | TLS-версия и шифры etcd, kube-apiserver | 3 |
| 24 | Шифрование secrets в etcd | 14 |
| 25 | ImagePolicyWebhook | 19 |
| 26 | Cilium с WireGuard | 16 |
| 27 | Политики Cilium, mutual authentication | 2, 16 |
| 28 | Falco: обнаружение доступа к памяти | 22, 23 |
| 29 | Харденинг Docker | 11, 17 |
| 30 | Istio PeerAuthentication | 16 |

## Мок-экзамены

- **Mock 01** ([`mock/01`](mock/01/README.MD)) - 18 задач по всем доменам.
- **Mock 02** ([`mock/02`](mock/02/README.MD)) - 17 задач.
- **Mock 03** ([`mock/03`](mock/03/README.MD)) - 18 задач, включая харденинг Docker.
- **Mock 04** ([`mock/04`](mock/04/README.MD)) - 12 задач, включая Cilium, апгрейд, anonymous auth.

Решайте на время (2 часа), без подсказок, цель - **75%+**.

## Темы без отдельной лабы (кандидаты в новые лабы)

Эти компетенции из программы CKS покрыты в курсе теорией и самостоятельными упражнениями, но
пока не имеют отдельной лабы с `check_result`:

| Предлагаемая лаба | Тема | Глава |
|-------------------|------|-------|
| 31 | Ingress с TLS и редиректом на HTTPS | 4 |
| 32 | Защита metadata-эндпоинта и kubelet API | 5 |
| 33 | Проверка бинарников платформы (sha512, cosign verify-blob) | 6 |
| 34 | RBAC: минимизация прав и пользователь через CSR | 7 |
| 35 | ServiceAccount: automount, отдельные SA, TokenRequest | 8 |
| 36 | Харденинг ОС: сервисы, порты, модули ядра | 11 |
| 37 | seccomp: Localhost-профиль и RuntimeDefault по умолчанию | 12 |
| 38 | SBOM: генерация (bom/trivy/syft) и анализ | 18 |
| 39 | ValidatingAdmissionPolicy и cosign-проверка образов | 19 |
| 40 | kubesec и KubeLinter: доведение манифеста до безопасного | 20 |
| 41 | Расследование инцидента: поиск процесса, изоляция пода | 23 |
| 42 | Иммутабельные поды: поиск и исправление | 24 |
