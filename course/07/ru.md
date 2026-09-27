# Глава 7. RBAC: минимизируем экспозицию

> **Что дальше.** Открываем домен **Cluster Hardening (15%)**. Кто и что может делать в
> кластере, определяет RBAC. На CKA вы создавали Role и RoleBinding; на CKS вопрос другой:
> как найти и убрать **лишние** права, какие права опасны сами по себе и как выдать доступ
> новому пользователю через сертификат.

## 7.1. Напоминание: четыре объекта

| Объект | Область | Что делает |
|--------|---------|------------|
| `Role` | namespace | набор разрешений в namespace |
| `ClusterRole` | кластер | набор разрешений на кластерные ресурсы или шаблон для всех ns |
| `RoleBinding` | namespace | привязывает Role **или ClusterRole** к субъектам в пределах ns |
| `ClusterRoleBinding` | кластер | привязывает ClusterRole ко всему кластеру |

Субъекты: `User`, `Group`, `ServiceAccount`. RBAC **только разрешающий**: запретов нет,
права складываются из всех привязок.

```mermaid
flowchart LR
    S["Subject<br>User / Group / SA"] --> B["RoleBinding /<br>ClusterRoleBinding"]
    B --> R["Role /<br>ClusterRole"]
    R --> P["verbs + resources"]
    style S fill:#673ab7,color:#fff
    style B fill:#f4b400,color:#000
    style R fill:#326ce5,color:#fff
```

Приём, который часто нужен: `RoleBinding` на `ClusterRole` - права ClusterRole действуют
**только в namespace биндинга**. Так переиспользуют одну ClusterRole в разных namespace.

## 7.2. Опасные права

Некоторые права эквивалентны cluster-admin или прямому пути к нему:

| Право | Почему опасно |
|-------|---------------|
| `*` на `*` | это cluster-admin |
| `get/list/watch` на `secrets` | чтение всех токенов и паролей в ns (list отдаёт содержимое!) |
| `create` на `pods` / `deployments` | запуск пода с любым SA ns или privileged → побег на ноду |
| `create` на `pods/exec`, `pods/attach` | shell в чужих контейнерах |
| `escalate`, `bind` на roles | выдать себе больше прав, чем имеешь |
| `impersonate` на users/groups/SA | выполнять запросы от чужого имени |
| `create` на `serviceaccounts/token` | выпускать токены чужих SA |
| `update/patch` на `nodes`, `nodes/proxy` | доступ к kubelet API через apiserver |
| права на `certificatesigningrequests/approval` | выпуск сертификатов для любых пользователей |
| `create` на `validatingwebhookconfigurations` | перехват/блокировка любых запросов |

Обратите внимание: `list` на secrets возвращает **содержимое** секретов, а не только имена.

## 7.3. Аудит существующих прав

```bash
# что может конкретный субъект
kubectl auth can-i --list --as=jane -n dev
kubectl auth can-i create pods --as=system:serviceaccount:dev:ci -n dev
kubectl auth can-i '*' '*' --as=system:serviceaccount:dev:ci   # не cluster-admin ли?

# кто привязан к cluster-admin
kubectl get clusterrolebindings -o wide | grep cluster-admin

# все привязки, где фигурирует SA
kubectl get rolebindings,clusterrolebindings -A -o wide | grep 'dev/ci'

# содержимое роли
kubectl describe clusterrole <name>
```

Для крупных кластеров есть инструменты `rbac-tool`, `kubectl-who-can`, `rakkess`, но на
экзамене хватает `kubectl auth can-i` и `describe`.

## 7.4. Минимизация: типовые правки

Задача «уменьшить права» обычно выглядит так: SA/пользователю выдана широкая роль, нужно
оставить только конкретные глаголы и ресурсы.

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: pod-reader
  namespace: dev
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "list", "watch"]
- apiGroups: [""]
  resources: ["configmaps"]
  resourceNames: ["app-config"]     # только конкретный объект
  verbs: ["get"]
```

Императивно - быстрее:

```bash
kubectl -n dev create role pod-reader --verb=get,list,watch --resource=pods
kubectl -n dev create rolebinding pod-reader --role=pod-reader --serviceaccount=dev:ci
kubectl -n dev create rolebinding jane-view --clusterrole=view --user=jane
```

Имейте в виду:

- `resourceNames` не работает с `list`, `watch`, `create`, `deletecollection` - для этих
  глаголов имя ещё неизвестно или не проверяется;
- `roleRef` в биндинге **неизменяем** - чтобы поменять роль, биндинг удаляют и создают заново;
- встроенные `view`/`edit`/`admin` - агрегированные роли; `edit` позволяет читать secrets и
  запускать поды с любым SA namespace.

## 7.5. Новый пользователь через CSR

В Kubernetes нет объекта User: пользователь - это CN сертификата (группы - поля O). Выдаём
доступ пользователю `john`:

```bash
openssl genrsa -out john.key 2048
openssl req -new -key john.key -out john.csr -subj "/CN=john/O=developers"

cat <<YAML | kubectl apply -f -
apiVersion: certificates.k8s.io/v1
kind: CertificateSigningRequest
metadata:
  name: john
spec:
  request: $(base64 -w0 < john.csr)
  signerName: kubernetes.io/kube-apiserver-client
  expirationSeconds: 86400
  usages: ["client auth"]
YAML

kubectl certificate approve john
kubectl get csr john -o jsonpath='{.status.certificate}' | base64 -d > john.crt

kubectl -n development create role developer --verb=create,list,get --resource=pods
kubectl -n development create rolebinding developer-john --role=developer --user=john

kubectl config set-credentials john --client-key=john.key --client-certificate=john.crt --embed-certs
kubectl config set-context john --cluster=kubernetes --user=john --namespace=development
kubectl --context=john get pods
```

Отозвать отдельный клиентский сертификат в Kubernetes **нельзя** - только удалить привязки
RBAC и ждать истечения. Поэтому `expirationSeconds` - хорошая практика.

## 7.6. Сертификаты и kubeconfig

Полезные команды для задач про контексты и сертификаты:

```bash
kubectl config get-contexts -o name
kubectl config view --raw -o jsonpath='{.users[?(@.name=="admin")].user.client-certificate-data}' \
  | base64 -d | openssl x509 -noout -subject -enddate
```

Субъект с `O=system:masters` - это группа, которая **обходит RBAC полностью**. Такие
сертификаты (например, из `admin.conf`) нельзя раздавать людям; начиная с 1.29, kubeadm
создаёт `super-admin.conf` отдельно, а `admin.conf` привязан к `kubeadm:cluster-admins`
через обычный ClusterRoleBinding.

## 7.7. Best practices

- **Least privilege**: namespace-роли вместо кластерных, конкретные глаголы вместо `*`.
- **Не раздавайте опасные права** (раздел 7.2) без осознанной необходимости.
- **Группы вместо пользователей** в биндингах - проще отзывать доступ.
- **Никаких `system:masters`** для людей и сервисов.
- **Регулярно проверяйте** `can-i --list` для SA приложений и привязки к `cluster-admin`.
- **Короткоживущие креды**: `expirationSeconds` в CSR, OIDC для людей.

## 7.8. Итоги главы

- Role/ClusterRole задают права, RoleBinding/ClusterRoleBinding привязывают их к субъектам.
- RoleBinding на ClusterRole ограничивает её одним namespace.
- Опасны: `*`, secrets, create pods, exec, escalate/bind, impersonate, nodes/proxy, CSR approval.
- `list` на secrets отдаёт содержимое; `edit` читает secrets.
- Аудит - `kubectl auth can-i --list --as=...`.
- Пользователь = CN сертификата, группа = O; `system:masters` обходит RBAC.

## 7.9. Вопросы для самопроверки

1. Почему право `create pods` фактически даёт доступ к secrets namespace?
2. Чем опасны глаголы `escalate`, `bind` и `impersonate`?
3. Как проверить, что SA `dev:ci` не имеет прав cluster-admin?
4. Почему нельзя поменять `roleRef` у существующего RoleBinding?
5. Опишите шаги выдачи доступа новому пользователю через CSR.
6. Как отозвать доступ пользователя с валидным сертификатом?

## Практика

Контексты и сертификаты пользователей в kubeconfig:

🧪 Лаба 01: [tasks/cks/labs/01](../../labs/01/README.MD)

Минимизация RBAC и создание пользователя через CSR - задачи **11 (RBAC)** и **16 (user john)**
мок-экзамена:

🧪 Мок 01: [tasks/cks/mock/01](../../mock/01/README.MD)

---
[Оглавление](../README_RU.md) · [Глава 6](../06/ru.md) · [Глава 8](../08/ru.md)
