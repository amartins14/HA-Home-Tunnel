# Contributing

Home Tunnel is a self-hosted project with two separately deployed parts: a Home
Assistant app and an IIS relay. Changes to their pairing protocol must preserve
compatibility or document the required matched update for both sides.

## Run the existing checks

The repository verification workflow runs the same checks on pull requests and
pushes:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-test.txt
.venv/bin/python -m unittest discover -s tests -v
docker build --tag home-tunnel-check home-assistant
```

The relay checks require Windows with the .NET Framework 4.8 compiler and runtime.
From PowerShell:

```powershell
$compiler = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
$source = (Resolve-Path 'relay\App_Code').Path
& $compiler /nologo /out:RelayTests.exe /r:System.Web.dll /r:System.Web.Extensions.dll /r:System.Configuration.dll /r:System.Core.dll (Join-Path $source 'HaTunnel.cs') (Join-Path $source 'RelayState.cs') (Resolve-Path 'tests\RelayTests.cs').Path
if ($LASTEXITCODE -ne 0) { throw 'Relay compilation failed' }
Copy-Item 'tests\RelayTests.exe.config' 'RelayTests.exe.config'
& .\RelayTests.exe
if ($LASTEXITCODE -ne 0) { throw 'Relay checks failed' }
```

Do not run diagnostic scripts against a production relay unless their procedure
explicitly says they are read-only. Never include real pairing codes, connector
keys, metrics tokens, cookies, signed URLs, or unredacted logs in a change.

## Release scope

The supported hosting target is currently IIS with classic ASP.NET Framework 4.8
and URL Rewrite. Pull requests should not imply support for other relay hosts.
Before a stable release, require green verification checks for the exact commit,
validate a fresh relay deployment on a clean IIS host, verify pairing and rollback,
and review the security limitations in `docs/SECURITY.md`. The development version
must remain marked as a development build until those checks are complete.

Development tags matching `v*-dev` publish GitHub prereleases only after the
verification workflow succeeds. They include a relay ZIP and changelog notes and
are explicitly marked as unsuitable for production. Stable releases remain a
separate, deliberate step after all stable-release checks above pass; do not move
the development manifest to a stable version before then.
