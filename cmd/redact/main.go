package main

import (
	"context"
	"fmt"
	"os"

	dlp "cloud.google.com/go/dlp/apiv2"
	"github.com/davecgh/go-spew/spew"
	"golang.org/x/xerrors"
	dlppb "google.golang.org/genproto/googleapis/privacy/dlp/v2"
)

func main() {
	ctx := context.Background()
	if err := redact(ctx); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func redact(ctx context.Context) error {
	c, err := dlp.NewClient(ctx)
	if err != nil {
		return xerrors.Errorf("issue creating client: %w", err)
	}

	req := &dlppb.InspectContentRequest{
		// TODO: Fill request struct fields.
	}
	resp, err := c.InspectContent(ctx, req)
	if err != nil {
		return xerrors.Errorf("issue inspecting client: %w", err)
	}
	spew.Dump(resp)
	return nil
}
