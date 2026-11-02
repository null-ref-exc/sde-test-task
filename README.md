# Запуск

Все команды выполняются из корня проекта

Возможны два режима:

- **Docker / Production** — API без Swagger UI и HTTP OpenAPI
- **Локально / Development** — API с интерактивной документацией Swagger UI

## Production в Docker

### Требования

Нужен Docker Engine с Linux-контейнерами и Docker Compose v2 или новее. В Windows запустите Docker Desktop в режиме Linux containers. Для сборки образа локальный .NET SDK не требуется; первая сборка скачивает базовые образы и NuGet-пакеты.

### Настройки

Редактируйте `appsettings.Container.json` рядом с `compose.yaml`:

```json
{
  "Scanning": {
    "MaxParallelScans": 2,
    "QueueCapacity": 100,
    "DemoDurationMilliseconds": 5000
  },
  "Logging": {
    "LogLevel": {
      "Default": "Information",
      "Microsoft.AspNetCore": "Warning",
      "Microsoft.AspNetCore.HttpLogging.HttpLoggingMiddleware": "Information",
      "Microsoft.EntityFrameworkCore.Database.Command": "Warning"
    }
  }
}
```

Допустимы 1–32 работника, ёмкость очереди 1–10000 и задержка сканера 1–300000 мс.

Compose подключает этот файл только для чтения как `/app/appsettings.Production.json`. Он перекрывает соответствующие настройки встроенного `appsettings.json`.

Dockerfile устанавливает окружение `Production` и внутренний порт `8080`. Compose публикует API только на `127.0.0.1:5080`.

### Запуск, проверка и остановка:

```sh
docker compose up --build -d
```

API доступен по `http://localhost:5080/api/...`

Остановка и удаление контейнера:

```sh
docker compose down
```

## Локально с документацией

### Подготовка и запуск

Нужен .NET 10 SDK. Выполните:

```sh
dotnet restore VulnerabilityTracker.slnx
dotnet tool restore
dotnet run --project src/VulnerabilityTracker.Api --launch-profile http
```

Команды одинаковы для shell и PowerShell. Профиль `http` из `Properties/launchSettings.json` устанавливает `ASPNETCORE_ENVIRONMENT=Development` и адрес `http://localhost:5080`

Если порт уже занят, запустите локальный API на другом порту:

```sh
dotnet run --project src/VulnerabilityTracker.Api --launch-profile http -- --urls http://localhost:5081
```

### Документация и настройки

Для стандартного порта откройте:

- Swagger UI: `http://localhost:5080/swagger/index.html`.
- OpenAPI JSON: `http://localhost:5080/openapi/v1.json`.

Локальный запуск читает `src/VulnerabilityTracker.Api/appsettings.json` и, при наличии, `appsettings.Development.json` в той же папке. Корневой `appsettings.Container.json` используется только при подключении через Docker Compose.

При сборке также генерируются `generated/openapi.json` и `generated/http/Requests.http`

# Немного о принятых решениях

## Тесты

Обычные тесты:

```sh
dotnet test VulnerabilityTracker.slnx -c Release
```

## E2E тесты

Так же были написаны E2E тесты, они описаны в [e2e/README.md](e2e/README.md).

## Сканер

Сканер не скачивает репозиторий: он выбирает существующие уязвимости трекера и генерирует вымышленные файлы и диапазоны строк. Проверяется только формат HTTP(S) URL. При пустом списке уязвимостей результат содержит пустой `findings`
