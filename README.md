# quicksheet-tls-ext

TLS certificate expiry + issuer checker for [QuickSheet](https://github.com/cemheren/QuickSheet).

## Install

Type into any cell in QuickSheet:

```
ext: github:<your-user>/quicksheet-tls-ext
```

QuickSheet clones the repo, reads the manifest, and registers the `tls` prefix.

## Use

```
tls: github.com, 1, 4
```

Fills 4 rows starting at the cell:

```
github.com:443
expires in 87d
issuer: Sectigo Limited
cn: github.com
```

You can also point at a non-443 port:

```
tls: smtp.gmail.com:465, 1, 4
```

## Why

Cert expiry is the kind of fact you want at-a-glance, not buried in a monitoring
dashboard. A few rows of `tls: …` in your wallpaper-mode QuickSheet gives you a
quiet, ambient overview of which of your hosts are about to bite.

## Build

Requires .NET 9. Zero NuGet dependencies — just `System.Net.Security` from BCL.

```
dotnet build TlsExtension.csproj
```

## Protocol

Reads JSON lines on stdin, writes JSON lines on stdout. See QuickSheet's main
README for the full extension protocol spec.

## License

MIT
