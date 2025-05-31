FROM golang:stretch

RUN apt-get update && apt-get install -y unzip && rm -rf /var/lib/apt/lists/*
ENV GO111MODULE=on
RUN go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
RUN go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
ADD https://github.com/protocolbuffers/protobuf/releases/download/v3.15.5/protoc-3.15.5-linux-x86_64.zip /
RUN unzip /protoc-3.15.5-linux-x86_64.zip
CMD ["/bin/bash"]
