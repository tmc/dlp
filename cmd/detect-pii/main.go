// Command redact-pii strips personally identifiable information (PII) from input.
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

var (

	// ErrFindingsPresent is a sentinal error to indicate findings are present.
	ErrFindingsPresent = errors.New("detect-pii: findings present")
	// ErrMissingProjectID is a sentinal error to indicate a missing project ID.
	ErrMissingProjectID = errors.New("detect-pii: missing project ID")
)

type detectConfig struct {
	Filename   string
	Likelihood string
	InfoTypes  []*dlppb.InfoType
	Verbosity  int

	Redact    bool
	ImageMode bool

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

		Redact:    *flagRedact,
		ImageMode: *flagImage,
	}
	for _, it := range strings.Split(*flagInfoTypes, ",") {
		c.InfoTypes = append(c.InfoTypes, &dlppb.InfoType{Name: it})
	}
	if err := run(c); err != nil {
		if errors.Is(err, ErrFindingsPresent) {
			os.Exit(2)
		}
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run(c *detectConfig) error {
	input, err := fileToReader(c.Filename)
	if err != nil {
		return fmt.Errorf("issue opening input: %w", err)
	}
	c.Content, err = ioutil.ReadAll(input)
	if err != nil {
		return fmt.Errorf("issue reading input: %w", err)
	}

	ctx := context.Background()
	rfunc := c.detect
	if c.Redact {
		rfunc = c.redact
		if c.ImageMode {
			rfunc = c.redactImage
		}
	}

	if err := rfunc(ctx); err != nil {
		if err == ErrFindingsPresent {
			if c.Verbosity == 1 {
				fmt.Fprintln(os.Stderr, "findings present:", c.Filename)
			}
		}
		return err
	}
	return nil
}

func getGCPProjectID(ctx context.Context) (string, error) {
	projectID := os.Getenv("GCP_PROJECT")
	if projectID == "" {
		fmt.Println("empty pid")
		credentials, err := google.FindDefaultCredentials(ctx)
		if err != nil {
			fmt.Fprintln(os.Stderr, "issue looking up default credentials:", err)
		}
		projectID = credentials.ProjectID
	}
	if projectID == "" {
		return "", ErrMissingProjectID
	}
	return projectID, nil
}

func (dc *detectConfig) detect(ctx context.Context) error {
	c, err := dlp.NewClient(ctx)
	if err != nil {
		return fmt.Errorf("issue creating client: %w", err)
	}

	projectID, err := getGCPProjectID(ctx)
	if err != nil {
		return err
	}
	// Assemble inspection request.
	req := &dlppb.InspectContentRequest{
		Parent: fmt.Sprintf("projects/%v", projectID),
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

	projectID, err := getGCPProjectID(ctx)
	if err != nil {
		return err
	}
	transformation := redactionTransformation()
	// Holy indentation batman.
	req := &dlppb.DeidentifyContentRequest{
		Parent: fmt.Sprintf("projects/%v", projectID),
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

	projectID, err := getGCPProjectID(ctx)
	if err != nil {
		return err
	}
	req := &dlppb.RedactImageRequest{
		Parent: fmt.Sprintf("projects/%v", projectID),
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
			Transformation: &dlppb.PrimitiveTransformation_ReplaceWithInfoTypeConfig{
				ReplaceWithInfoTypeConfig: &dlppb.ReplaceWithInfoTypeConfig{},
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
