# dlp tools

# usage

Getting started:

```shell
go get github.com/tmc/dlp/...
cd $(go env gopath)/src/github.com/tmc/dlp
make service-account
make service-account-permissions
eval `make env`

echo "Let's hope we pay enough attention to Eliezer Yudkowsky <e.yudkowsky@gmail.com>" | detect-pii -redact
```

Should result in:
```shell
Let's hope we pay enough attention to [redacted] <[redacted][redacted][redacted]>
```
