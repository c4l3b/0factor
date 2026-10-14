# AOT needs the native toolchain (clang) from the -aot SDK image. Build per arch on a native runner: AOT doesn't cross-compile under QEMU.
FROM mcr.microsoft.com/dotnet/sdk:10.0-noble-aot AS build
WORKDIR /src
COPY global.json ./
COPY src/ZeroFactor/ZeroFactor.csproj src/ZeroFactor/
RUN dotnet restore src/ZeroFactor -r linux-$(uname -m | sed 's/x86_64/x64/;s/aarch64/arm64/')
COPY src/ src/
RUN dotnet publish src/ZeroFactor -c Release -r linux-$(uname -m | sed 's/x86_64/x64/;s/aarch64/arm64/') --no-restore -o /app \
 && mkdir -p /data

# Chiseled = distroless: no shell, no package manager, non-root `app` user (UID 1654).
FROM mcr.microsoft.com/dotnet/runtime-deps:10.0-noble-chiseled
WORKDIR /app
COPY --from=build /app/ZeroFactor /app/appsettings.json ./
COPY --from=build --chown=1654:1654 /data /data
ENV ASPNETCORE_HTTP_PORTS=8080 ZF_DATA_DIR=/data
EXPOSE 8080
VOLUME /data
ENTRYPOINT ["./ZeroFactor"]
