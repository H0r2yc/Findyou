SET CGO_ENABLED=1
SET GOOS=windows
SET GOARCH=amd64
go build -ldflags "-s -w" workflow.go