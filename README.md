# dlp tools

# usage

Getting started:

```sh
go get github.com/tmc/dlp/...
cd $(go env gopath)/src/github.com/tmc/dlp
make service-account
make service-account-permissions
eval `make env`

echo "Andrew Yang <yanggang@gmail.com>" | redact
```

Should result in:
```sh
xxx <xxx>
```
