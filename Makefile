.PHONY: proto clean

proto:
	go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
	mkdir -p proto/generated
	cd proto && protoc --go_out=../proto/generated --go_opt=paths=source_relative *.proto

clean:
	rm -f proto/generated/*.pb.go
