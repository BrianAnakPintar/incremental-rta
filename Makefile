.PHONY: proto clean clean-proto clean-dots

proto:
	go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
	mkdir -p proto/generated
	cd proto && protoc --go_out=../proto/generated --go_opt=paths=source_relative *.proto

clean-proto:
	# remove generated protobuf files
	rm -f proto/generated/*.pb.go

clean-dots:
	# remove any .dot graph files found in the repository (safe for zero matches)
	-find . -name '*.dot' -type f -print0 | xargs -0 rm -f -- || true

clean: clean-proto clean-dots
