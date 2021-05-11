// Command redact strips personally identifiable information (PII) from input.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"regexp"
	"strings"

	dlp "cloud.google.com/go/dlp/apiv2"
	"golang.org/x/oauth2/google"
	dlppb "google.golang.org/genproto/googleapis/privacy/dlp/v2"
)

// ErrFindingsPresent is a sentinal error to indicate findings are present.
var ErrFindingsPresent = errors.New("detect-pii: findings present")

type detectConfig struct {
	Filename   string
	Likelihood string
	InfoTypes  []*dlppb.InfoType
	Verbosity  int

	Content    []byte
	LineStarts []int
}

func main() {
	flagFilename := flag.String("f", "-", "input file to read")
	flagRedact := flag.Bool("redact", false, "enable redaction")
	flagImage := flag.Bool("image", false, "image mode (redaction only)")
	flagLiklihood := flag.String("liklihood", "LIKELY", "liklihood threshold.")
	flagInfoTypes := flag.String("info-types", "CREDIT_CARD_NUMBER,CREDIT_CARD_TRACK_NUMBER,EMAIL_ADDRESS,ETHNIC_GROUP,FIRST_NAME,GCP_CREDENTIALS,ICD9_CODE,ICD10_CODE,IP_ADDRESS,LAST_NAME,LOCATION,PASSPORT,PERSON_NAME,PHONE_NUMBER,STREET_ADDRESS", "info type list to scan for.")

	flagVerbosity := flag.Int("v", 0, "verbosity level")
	flag.Parse()

	c := &detectConfig{
		Filename:   *flagFilename,
		Likelihood: *flagLiklihood,
		Verbosity:  *flagVerbosity,
	}
	for _, it := range strings.Split(*flagInfoTypes, ",") {
		c.InfoTypes = append(c.InfoTypes, &dlppb.InfoType{Name: it})
	}
	input, err := fileToReader(c.Filename)
	if err != nil {
		fmt.Fprintln(os.Stderr, fmt.Errorf("issue opening input: %w", err))
		os.Exit(1)
	}
	c.Content, err = ioutil.ReadAll(input)
	if err != nil {
		fmt.Fprintln(os.Stderr, fmt.Errorf("issue reading input: %w", err))
		os.Exit(1)
	}

	ctx := context.Background()
	rfunc := c.detect
	if *flagRedact {
		rfunc = c.redact
		if *flagImage {
			rfunc = c.redactImage
		}
	}

	if err := rfunc(ctx); err != nil {
		if err == ErrFindingsPresent {
			if *flagVerbosity == 1 {
				fmt.Fprintln(os.Stderr, fmt.Errorf("%w: %v", err, *flagFilename))
			}
			os.Exit(2)
		} else {
			fmt.Fprintln(os.Stderr, err)
		}
		os.Exit(1)
	}
}

func getGCPProjectID(ctx context.Context) string {
	projectID := os.Getenv("GCP_PROJECT")
	if projectID == "" {
		credentials, err := google.FindDefaultCredentials(ctx)
		if err != nil {
			fmt.Fprintln(os.Stderr, "issue looking up default credentials:", err)
		}
		fmt.Printf("%+v\n", credentials)
		projectID = credentials.ProjectID
	}
	return projectID
}

func (dc *detectConfig) detect(ctx context.Context) error {
	c, err := dlp.NewClient(ctx)
	if err != nil {
		return fmt.Errorf("issue creating client: %w", err)
	}

	// Assemble inspection request.
	req := &dlppb.InspectContentRequest{
		Parent: fmt.Sprintf("projects/%v", getGCPProjectID(ctx)),
		InspectConfig: &dlppb.InspectConfig{
			InfoTypes:     dc.InfoTypes,
			MinLikelihood: dlppb.Likelihood(dlppb.Likelihood_value[dc.Likelihood]),
		},
		Item: &dlppb.ContentItem{
			DataItem: &dlppb.ContentItem_ByteItem{
				ByteItem: &dlppb.ByteContentItem{
					Type: dlppb.ByteContentItem_TEXT_UTF8,
					Data: dc.Content,
				},
			},
		},
	}
	resp, err := c.InspectContent(ctx, req)
	if err != nil {
		return fmt.Errorf("issue redacting: %w", err)
	}
	findings := resp.Result.GetFindings()
	if dc.Verbosity == 1 {
		fmt.Println(len(findings))
	}
	shouldSkip := false
	if dc.Verbosity == 2 {
		for _, f := range findings {
			row, column, _ := dc.LocationToRowCol(f.GetLocation())
			fmt.Printf("%v:%v:%v: detect-pii detected %v %v\n", dc.Filename, row, column, f.GetLikelihood(), f.GetInfoType().GetName())
		}
	}
	if len(findings) > 0 && !shouldSkip {
		return ErrFindingsPresent
	}
	return nil
}

func (dc *detectConfig) LocationToRowCol(loc *dlppb.Location) (row int, col int, err error) {
	if dc.LineStarts == nil {
		re := regexp.MustCompile("(?m:^)")
		spots := re.FindAllIndex(dc.Content, -1)
		for _, spot := range spots {
			dc.LineStarts = append(dc.LineStarts, spot[0])
		}
	}

	row = -1
	col = -1
	for i, lineStart := range dc.LineStarts {
		if int64(lineStart) > loc.ByteRange.Start {
			break
		}
		row = i + 1
		col = int(loc.ByteRange.Start) - lineStart
	}

	// TODO(tmc): add skipping

	return row, col, nil
}

func (dc *detectConfig) redact(ctx context.Context) error {
	c, err := dlp.NewClient(ctx)
	if err != nil {
		return fmt.Errorf("issue creating client: %w", err)
	}

	transformation := redactionTransformation()
	// Holy indentation batman.
	req := &dlppb.DeidentifyContentRequest{
		Parent: fmt.Sprintf("projects/%v", getGCPProjectID(ctx)),
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
					Type: dlppb.ByteContentItem_TEXT_UTF8,
					Data: dc.Content,
				},
			},
		},
	}
	resp, err := c.DeidentifyContent(ctx, req)
	if err != nil {
		return fmt.Errorf("issue redacting: %w", err)
	}
	fmt.Println(string(resp.GetItem().GetByteItem().GetData()))
	return nil
}

func (dc *detectConfig) redactImage(ctx context.Context) error {
	c, err := dlp.NewClient(ctx)
	if err != nil {
		return fmt.Errorf("issue creating client: %w", err)
	}

	// redactionConfig := &dlppb.RedactImageRequest_ImageRedactionConfig_RedactAllText{
	// 	RedactAllText: true,
	// }

	infoTypes := dc.InfoTypes

	// Convert the info type strings to a list of types to redact in the image.
	var ir []*dlppb.RedactImageRequest_ImageRedactionConfig
	for _, it := range infoTypes {
		ir = append(ir, &dlppb.RedactImageRequest_ImageRedactionConfig{
			Target: &dlppb.RedactImageRequest_ImageRedactionConfig_InfoType{
				InfoType: it,
			},
		})
	}

	req := &dlppb.RedactImageRequest{
		Parent: fmt.Sprintf("projects/%v", getGCPProjectID(ctx)),
		InspectConfig: &dlppb.InspectConfig{
			InfoTypes:     dc.InfoTypes,
			MinLikelihood: dlppb.Likelihood(dlppb.Likelihood_value[dc.Likelihood]),
		},
		ImageRedactionConfigs: ir,
		ByteItem: &dlppb.ByteContentItem{
			Type: dlppb.ByteContentItem_IMAGE,
			Data: dc.Content,
		},
	}

	resp, err := c.RedactImage(ctx, req)
	if err != nil {
		return fmt.Errorf("issue redacting: %w", err)
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
