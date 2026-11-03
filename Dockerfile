FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src
COPY NoxRemoteAI.CloudDevices/NoxRemoteAI.CloudDevices.csproj NoxRemoteAI.CloudDevices/
RUN dotnet restore NoxRemoteAI.CloudDevices/NoxRemoteAI.CloudDevices.csproj
COPY NoxRemoteAI.CloudDevices/ NoxRemoteAI.CloudDevices/
RUN dotnet publish NoxRemoteAI.CloudDevices/NoxRemoteAI.CloudDevices.csproj -c Release -o /app/publish --no-restore
FROM mcr.microsoft.com/dotnet/aspnet:10.0
WORKDIR /app
COPY --from=build /app/publish .
ENV ASPNETCORE_URLS=http://0.0.0.0:10000
EXPOSE 10000
ENTRYPOINT ["dotnet","NoxRemoteAI.CloudDevices.dll"]
