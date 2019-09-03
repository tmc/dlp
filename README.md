# dlp tools

# usage

Getting started:

```sh
go get github.com/tmc/dlp/...
cd $(go env gopath)/src/github.com/tmc/dlp
make service-account
make service-account-permissions
eval `make env`

echo "I might make a contribution to Andrew Yang <yanggang@gmail.com>" | redact-pii
```

Should result in:
```sh
I might make a contribution to [redacted] <[redacted]>
```
