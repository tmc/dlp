package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"

	dlp "cloud.google.com/go/dlp/apiv2"
	"github.com/davecgh/go-spew/spew"
	"golang.org/x/xerrors"
	dlppb "google.golang.org/genproto/googleapis/privacy/dlp/v2"
)

func main() {
	flagInput := flag.String("f", "-", "input file to read")
	flag.Parse()

	in, err := fileToReader(*flagInput)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	ctx := context.Background()
	if err := redact(ctx, in); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func redact(ctx context.Context, input io.Reader) error {
	c, err := dlp.NewClient(ctx)
	if err != nil {
		return xerrors.Errorf("issue creating client: %w", err)
	}

	content, err := ioutil.ReadAll(input)
	if err != nil {
		return err
	}

	req := &dlppb.InspectContentRequest{
		// TODO: Fill request struct fields.
		Parent: fmt.Sprintf("projects/%v", os.Getenv("PROJECT_ID")),
		Item: &dlppb.ContentItem{
			DataItem: &dlppb.ContentItem_ByteItem{
				ByteItem: &dlppb.ByteContentItem{
					Data: content,
				},
			},
		},
	}
	resp, err := c.InspectContent(ctx, req)
	if err != nil {
		return xerrors.Errorf("issue inspecting client: %w", err)
	}
	spew.Dump(resp)
	return nil
}

func fileToReader(path string) (io.Reader, error) {
	if path == "-" {
		return os.Stdin, nil
	}
	return os.Open(path)
}
