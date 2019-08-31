// Command redact strips personally identifiable information (PII) from input.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"

	dlp "cloud.google.com/go/dlp/apiv2"
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

	// Holy indentation batman.
	req := &dlppb.DeidentifyContentRequest{
		Parent: fmt.Sprintf("projects/%v", os.Getenv("PROJECT_ID")),
		DeidentifyConfig: &dlppb.DeidentifyConfig{
			Transformation: &dlppb.DeidentifyConfig_InfoTypeTransformations{
				InfoTypeTransformations: &dlppb.InfoTypeTransformations{
					Transformations: []*dlppb.InfoTypeTransformations_InfoTypeTransformation{
						{
							PrimitiveTransformation: &dlppb.PrimitiveTransformation{
								Transformation: &dlppb.PrimitiveTransformation_ReplaceConfig{
									ReplaceConfig: &dlppb.ReplaceValueConfig{
										NewValue: &dlppb.Value{
											Type: &dlppb.Value_StringValue{
												StringValue: "xxx",
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
		Item: &dlppb.ContentItem{
			DataItem: &dlppb.ContentItem_ByteItem{
				ByteItem: &dlppb.ByteContentItem{
					Data: content,
				},
			},
		},
	}
	resp, err := c.DeidentifyContent(ctx, req)
	if err != nil {
		return xerrors.Errorf("issue redacting: %w", err)
	}
	fmt.Println(string(resp.GetItem().GetByteItem().GetData()))
	return nil
}

func fileToReader(path string) (io.Reader, error) {
	if path == "-" {
		return os.Stdin, nil
	}
	return os.Open(path)
}
