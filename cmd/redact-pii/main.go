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
	flagImage := flag.Bool("image", false, "input file to read")
	flag.Parse()

	in, err := fileToReader(*flagInput)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	ctx := context.Background()
	rfunc := redact
	if *flagImage {
		rfunc = redactImage
	}
	if err := rfunc(ctx, in); err != nil {
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

	transformation := redactionTransformation()
	// Holy indentation batman.
	req := &dlppb.DeidentifyContentRequest{
		Parent: fmt.Sprintf("projects/%v", os.Getenv("PROJECT_ID")),
		DeidentifyConfig: &dlppb.DeidentifyConfig{
			Transformation: &dlppb.DeidentifyConfig_InfoTypeTransformations{
				InfoTypeTransformations: &dlppb.InfoTypeTransformations{
					Transformations: []*dlppb.InfoTypeTransformations_InfoTypeTransformation{transformation},
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

func redactImage(ctx context.Context, input io.Reader) error {
	c, err := dlp.NewClient(ctx)
	if err != nil {
		return xerrors.Errorf("issue creating client: %w", err)
	}

	content, err := ioutil.ReadAll(input)
	if err != nil {
		return err
	}

	// redactionConfig := &dlppb.RedactImageRequest_ImageRedactionConfig_RedactAllText{
	// 	RedactAllText: true,
	// }

	infoTypes := []string{
		"AGE", "CREDIT_CARD_NUMBER", "CREDIT_CARD_TRACK_NUMBER", "DATE", "DATE_OF_BIRTH", "DOMAIN_NAME", "EMAIL_ADDRESS", "ETHNIC_GROUP", "FEMALE_NAME", "FIRST_NAME", "GCP_CREDENTIALS", "GENDER", "IBAN_CODE", "ICD9_CODE", "ICD10_CODE", "IMEI_HARDWARE_ID", "IP_ADDRESS", "LAST_NAME", "LOCATION", "MAC_ADDRESS", "MAC_ADDRESS_LOCAL", "MALE_NAME", "MEDICAL_TERM", "PASSPORT", "PERSON_NAME", "PHONE_NUMBER", "STREET_ADDRESS", "SWIFT_CODE", "TIME", "URL",
	}

	var i []*dlppb.InfoType
	for _, it := range infoTypes {
		i = append(i, &dlppb.InfoType{Name: it})
	}

	// Convert the info type strings to a list of types to redact in the image.
	var ir []*dlppb.RedactImageRequest_ImageRedactionConfig
	for _, it := range infoTypes {
		ir = append(ir, &dlppb.RedactImageRequest_ImageRedactionConfig{
			Target: &dlppb.RedactImageRequest_ImageRedactionConfig_InfoType{
				InfoType: &dlppb.InfoType{Name: it},
			},
		})
	}

	req := &dlppb.RedactImageRequest{
		Parent:                fmt.Sprintf("projects/%v", os.Getenv("PROJECT_ID")),
		InspectConfig:         &dlppb.InspectConfig{InfoTypes: i},
		ImageRedactionConfigs: ir,
		ByteItem: &dlppb.ByteContentItem{
			Type: dlppb.ByteContentItem_IMAGE,
			Data: content,
		},
	}

	resp, err := c.RedactImage(ctx, req)
	if err != nil {
		return xerrors.Errorf("issue redacting: %w", err)
	}
	os.Stdout.Write(resp.RedactedImage)
	return nil
}

func redactionTransformation() *dlppb.InfoTypeTransformations_InfoTypeTransformation {
	return &dlppb.InfoTypeTransformations_InfoTypeTransformation{
		PrimitiveTransformation: &dlppb.PrimitiveTransformation{
			Transformation: &dlppb.PrimitiveTransformation_ReplaceConfig{
				ReplaceConfig: &dlppb.ReplaceValueConfig{
					NewValue: &dlppb.Value{
						Type: &dlppb.Value_StringValue{
							StringValue: "[redacted]",
						},
					},
				},
			},
		},
	}
}

func fileToReader(path string) (io.Reader, error) {
	if path == "-" {
		return os.Stdin, nil
	}
	return os.Open(path)
}
