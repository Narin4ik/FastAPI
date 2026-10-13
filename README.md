# Private API Relay

Закрытый HTTPS/WSS-посредник на FastAPI для Discord, Telegram и других явно разрешённых API. Python **3.11+**, C#-адаптер для **.NET 8+**. Не требует root, TUN-интерфейса или установки VPN внутри Pterodactyl.

## Что умеет

- `POST /proxy`: передача API-запросов, JSON, формы, строк и бинарного тела через HTTPS.
- `WSS /tunnel?host=...&port=443`: двусторонний TCP-туннель. Подходит для HTTPS, Telegram long polling, Discord Gateway и загрузки файлов.
- C#-транспорт для `HttpClient` и `ClientWebSocket`, а также локальный HTTP CONNECT-мост для библиотек с настройкой прокси.
- Отдельные ключи ботов, временная блокировка после ошибок авторизации, лимиты запросов и соединений.
- Проверка DNS и соединение с проверенным IP, блокировка внутренних адресов, проверка сертификатов конечных API.

## Шифрование и границы защиты

Соединение бота с посредником использует HTTPS/WSS. Ключ посредника передаётся в заголовке внутри TLS; не в URL. Для `/tunnel` бот дополнительно устанавливает **своё TLS-соединение с Discord/Telegram внутри туннеля**. FastAPI пересылает байты и не расшифровывает токены бота. В `/proxy` TLS завершается на посреднике, который видит API-запрос в памяти и передаёт его конечному сервису снова через HTTPS.

Ключ посредника и токен Discord/Telegram — разные секреты. Не передавайте токен бота как `X-Proxy-Secret`. Приложение не сохраняет токены ботов на диск; ключи доступа хранятся в окружении сервера. Не логируйте тела запросов и заголовки в Nginx, CDN, библиотеке бота или APM. Доступ администратора к машине/контейнеру не защищается сетевым TLS.

Провайдер сети бота видит IP/домен посредника, время и объём трафика. Discord/Telegram видят исходящий IP посредника. Это не гарантия нераспознаваемого туннеля и не имитация российского сервиса: адрес сервера, домен, SNI и особенности трафика могут позволить классификацию. На исходящей стороне посредника остаются обычные соединения с Discord/Telegram. Для этого сервера нужен прямой доступ к ним.

**UDP, голос Discord и MTProto не реализованы.** Голос использует отдельный UDP-транспорт; TCP-сигнализация сама по себе не даёт голосовой связи. Это прокси приложения, не системный VPN. Не меняйте схему на произвольные TCP-порты ради голосового трафика.

## Запуск в Pterodactyl

1. Используйте Python 3.11+ и загрузите файлы репозитория в `/home/container`.
2. Установите зависимости: `python -m pip install -r requirements.txt`.
3. Сгенерируйте отдельный ключ для каждого бота:

   ```sh
   python -c 'import secrets; print(secrets.token_hex(32))'
   ```

4. Задайте переменные окружения в egg/startup-конфигурации:

   ```text
   RELAY_KEYS_JSON={"discord-bot":"<случайный ключ>","telegram-bot":"<другой случайный ключ>"}
   HOST=0.0.0.0
   PORT=<выделенный порт контейнера>
   ALLOW_INSECURE_TRANSPORT=false
   FORWARDED_ALLOW_IPS=<IP Nginx, который виден контейнеру>
   ```

5. Startup Command: `python server.py`.
6. Поставьте перед контейнером Nginx с валидным HTTPS-сертификатом и поддержкой WebSocket. Пример: [`examples/nginx.conf`](examples/nginx.conf).

При использовании Nginx **закройте прямой доступ из интернета к порту контейнера**. Только Nginx должен иметь к нему доступ. В Docker/Pterodactyl Nginx может быть виден не как `127.0.0.1`, а как адрес шлюза bridge-сети. В `FORWARDED_ALLOW_IPS` укажите именно доверенный адрес, не `*`: иначе клиент сможет подделать IP и признак HTTPS. На Nginx заголовки `X-Forwarded-*` должны перезаписываться, как в примере.

Вариант без Nginx: смонтируйте сертификат и ключ в контейнер и задайте `TLS_CERT_FILE` / `TLS_KEY_FILE`. Тогда приложение само обслуживает TLS на выделенном порту. Используйте действующий сертификат для домена посредника; не отключайте его проверку в ботах.

`.env.example` — справочник настроек. Файл `.env` **не загружается автоматически**. Секретов в исходниках нет; без корректного ключа сервер не стартует. После смены ключей перезапустите процесс. Один процесс Uvicorn: лимиты и временные блокировки находятся в памяти и сбрасываются при перезапуске. Для нескольких реплик нужен общий внешний лимитер.

## Подключение C#-бота

Скопируйте [`RelayTransport.cs`](examples/dotnet/RelayTransport.cs) в проект .NET 8+. Существующие адреса API и токены бота остаются в его библиотеке. Все нужные HTTP- и WebSocket-клиенты должны использовать посредник; настройка только REST-клиента не перенаправит Discord Gateway.

```csharp
using PrivateRelay;

var relay = new RelayTransport(
    new Uri("wss://relay.example.com/tunnel"),
    Environment.GetEnvironmentVariable("RELAY_KEY_ID")!,
    Environment.GetEnvironmentVariable("RELAY_SECRET")!);

// Передайте этот HttpClient в конструктор/конфигурацию SDK бота.
using var http = new HttpClient(relay.CreateHandler());
http.Timeout = TimeSpan.FromSeconds(120);
var response = await http.GetAsync("https://discord.com/api/v10/gateway");
```

Для WebSocket-клиента:

```csharp
using var handler = relay.CreateHandler();
using var invoker = new HttpMessageInvoker(handler, disposeHandler: false);
using var socket = new System.Net.WebSockets.ClientWebSocket();
await socket.ConnectAsync(
    new Uri("wss://gateway.discord.gg/?v=10&encoding=json"),
    invoker, CancellationToken.None);
// Heartbeat, Identify, reconnect/resume выполняет библиотека самого бота.
```

Если SDK принимает только `IWebProxy`, запустите CONNECT-мост **в том же контейнере, что и бот**:

```sh
# RELAY_SECRET задавайте в окружении, не аргументом командной строки.
export RELAY_ENDPOINT=wss://relay.example.com/tunnel
export RELAY_KEY_ID=discord-bot
dotnet run --project examples/dotnet --configuration Release -- bridge
```

В HTTP- и WebSocket-транспортах библиотеки задайте `new WebProxy("http://127.0.0.1:8787")`. Мост слушает только loopback и принимает HTTPS CONNECT на 443. Порт можно поменять через `LOCAL_PROXY_PORT`. У SDK могут быть разные настройки прокси для REST и Gateway; конкретная точка подключения зависит от названия и версии библиотеки. Сервис не требует менять Discord/Telegram протокол.

Проверочные режимы примера: `api` (GET Gateway) и `websocket` (первое сообщение Gateway без авторизации). В них нет реальных токенов бота.

## Отдельные API-запросы через `/proxy`

Заголовки соединения с посредником:

```text
X-Proxy-Key: telegram-bot
X-Proxy-Secret: <ключ посредника>
Content-Type: application/json
```

Тело запроса:

```json
{
  "method": "POST",
  "url": "https://api.telegram.org/bot<BOT_TOKEN>/sendMessage",
  "json": {"chat_id": 12345, "text": "Hello"},
  "timeout": 60
}
```

Для Discord передавайте `Authorization: Bot <BOT_TOKEN>` внутри поля `headers`. Внешние заголовки посредника не попадают к целевому API.

```csharp
using System.Net.Http.Json;

using var relayHttp = new HttpClient { BaseAddress = new Uri("https://relay.example.com") };
relayHttp.DefaultRequestHeaders.Add("X-Proxy-Key", Environment.GetEnvironmentVariable("RELAY_KEY_ID"));
relayHttp.DefaultRequestHeaders.Add("X-Proxy-Secret", Environment.GetEnvironmentVariable("RELAY_SECRET"));
var response = await relayHttp.PostAsJsonAsync("/proxy", new {
    method = "GET",
    url = "https://discord.com/api/v10/gateway"
});
```

Можно передать ровно одно поле тела: `json`, `data` (строка или словарь строк) либо `body_base64` (бинарное тело; для multipart также задайте `Content-Type` с boundary). `params` добавляет query-параметры. `/proxy` буферизует ответ в пределах лимита; для больших файлов используйте C#-транспорт через туннель.

Статус конечного API сохраняется, включая 429. Возвращаются `Content-Type`, `Content-Encoding`, `Content-Disposition`, `Retry-After`, `ETag`, `Last-Modified`, `X-RateLimit-*`. Редиректы не выполняются; `Location` и cookies ответа не передаются. Провайдерские cookies между ботами не переиспользуются. Тайм-аут включает весь запрос и ограничен 120 секундами; для Telegram long polling задавайте меньший polling timeout, например 50 секунд при proxy timeout 60.

## Разрешённые направления и лимиты

По умолчанию доступны `discord.com`, `gateway.discord.gg`, `*.gateway.discord.gg`, `cdn.discordapp.com`, `media.discordapp.net`, `api.telegram.org`. Wildcard распространяется только на поддомены указанного домена, а не на похожие названия. Resume-хосты Discord разрешаются в пределах `*.gateway.discord.gg`.

`ALLOWED_HOSTS` полностью заменяет список. Для другого API добавьте его точный домен; пустой список и `*` отклоняются. Только HTTPS/TCP 443; IP-литералы, loopback, private, link-local, multicast, IPv6 transition-адреса и смешанные DNS-ответы с внутренним IP блокируются. DNS проверяется на каждом новом исходящем соединении, после чего соединение открывается по проверенному IP с оригинальным TLS SNI и проверкой сертификата.

| Переменная | По умолчанию |
| --- | --- |
| `MAX_CONCURRENT` / `MAX_PER_KEY` | 64 / 16 активных запросов и туннелей |
| `REQUESTS_PER_MINUTE` | 120 запросов или открытий туннеля на ключ |
| `MAX_REQUEST_BYTES` / `MAX_RESPONSE_BYTES` | 2 MiB / 8 MiB для `/proxy` |
| `FAILED_THRESHOLD` / `FAILED_WINDOW_SECONDS` | 5 ошибок / 600 секунд |
| `BLOCK_SECONDS` | 600 секунд блокировки IP |
| `MAX_TRACKING_ENTRIES` | 4096 записей отслеживания |
| `CONNECT_TIMEOUT` / `REQUEST_TIMEOUT` | 10 / 120 секунд |
| `TUNNEL_IDLE_SECONDS` / `TUNNEL_MAX_SECONDS` | 180 / 86400 секунд |
| `MAX_FRAME_BYTES` | 65536; клиент отправляет блоки по 16 KiB |

Истечение срока туннеля/разрыв требует переподключения библиотеки бота. Стандартный Startup Command также ограничивает очередь кадров, отключает их сжатие и логирование адресов запросов. При запуске вручную через Uvicorn повторите соответствующие настройки из `server.py`; предпочтительно используйте `python server.py`.

Для разработки на локальной машине можно явно поставить `ALLOW_INSECURE_TRANSPORT=true`. На публичном сервере оставьте `false`. Нельзя считать сам `X-Forwarded-Proto` доказательством TLS без доверенного и изолированного reverse proxy.

## Переход со старой версии

`PROXY_SECRET_128` продолжает работать для ключа `default`, без изменения исходников. `/health` и формат `/proxy` сохранены; добавлены строгая проверка полей и обязательный HTTPS. Произвольные хосты теперь запрещены по умолчанию, разрешайте нужные домены явно. Вечный файловый `blacklist.txt` заменён временной блокировкой с ограниченным объёмом памяти; ручной IP-фильтр задавайте на firewall/Nginx.

## Проверки

```sh
python -m pip install -r requirements-dev.txt
ruff check .
ruff format --check .
python -m pytest -q
python -m tests.smoke
dotnet build examples/dotnet/RelayClient.csproj --configuration Release
python -m tests.dotnet_smoke
pip-audit -r requirements.txt
```

GitHub Actions выполняет эти проверки при push в `dev`/`main` и PR в `main`. Интеграционный тест проверяет HTTPS и WebSocket из C# через реальный локальный WSS, с доверенным тестовым сертификатом и включённой проверкой TLS. Реальные аккаунты Discord/Telegram не используются. `tests/tls_fixture.py` специально подменяет целевые адреса локальным стендом и **не предназначен для развёртывания**.
