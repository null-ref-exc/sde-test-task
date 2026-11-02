FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /source

COPY global.json Directory.Build.props NuGet.Config ./
COPY src/VulnerabilityTracker.Api/*.csproj src/VulnerabilityTracker.Api/
COPY src/VulnerabilityTracker.Application/*.csproj src/VulnerabilityTracker.Application/
COPY src/VulnerabilityTracker.Domain/*.csproj src/VulnerabilityTracker.Domain/
COPY src/VulnerabilityTracker.Infrastructure/*.csproj src/VulnerabilityTracker.Infrastructure/
COPY src/VulnerabilityTracker.Persistence/*.csproj src/VulnerabilityTracker.Persistence/
RUN dotnet restore src/VulnerabilityTracker.Api/VulnerabilityTracker.Api.csproj

COPY src/ src/
# Документация доступна через HTTP; генератор .http нужен только при разработке.
RUN dotnet publish src/VulnerabilityTracker.Api/VulnerabilityTracker.Api.csproj \
    -c Release --no-restore -o /app/publish \
    -p:UseAppHost=false -p:OpenApiGenerateDocuments=false -p:GenerateHttpRequests=false

FROM mcr.microsoft.com/dotnet/aspnet:10.0 AS runtime
WORKDIR /app
COPY --from=build /app/publish .
ENV ASPNETCORE_HTTP_PORTS=8080
ENV ASPNETCORE_ENVIRONMENT=Production
EXPOSE 8080
USER $APP_UID
ENTRYPOINT ["dotnet", "VulnerabilityTracker.Api.dll"]
