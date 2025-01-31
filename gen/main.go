package main

import (
	"fmt"
	sevpb "github.com/google/go-sev-guest/proto/sevsnp"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

var products = []*sevpb.SevProduct{
	{
		Name:            sevpb.SevProduct_SEV_PRODUCT_GENOA,
		MachineStepping: &wrapperspb.UInt32Value{Value: uint32(0)},
	},
}

func main() {
	for _, product := range products {
		fmt.Printf("%+v", product)
	}
}
