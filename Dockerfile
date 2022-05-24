FROM golang:latest as BUILDER

MAINTAINER zengchen1024<chenzeng765@gmail.com>

# build binary
WORKDIR /go/src/github.com/opensourceways/robot-gitee-synchronizer
COPY . .
RUN GO111MODULE=on CGO_ENABLED=0 go build -a -o robot-gitee-synchronizer .

# copy binary config and utils
FROM alpine:3.14
COPY  --from=BUILDER /go/src/github.com/opensourceways/robot-gitee-synchronizer/robot-gitee-synchronizer /opt/app/robot-gitee-synchronizer

ENTRYPOINT ["/opt/app/robot-gitee-synchronizer"]
