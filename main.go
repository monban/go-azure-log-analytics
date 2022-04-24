package loganalytics

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

/* The Client struct represents a connection to a Log Analytics instance.
Example:
	client := loganalytics.Client{
		WorkspaceID: WORKSPACE,
		SharedKey:   SHARED_KEY,
		CustomTable: "foo",
	}
	result, err := client.Log(struct {
		Foo string `json:"foo"`
	}{Foo: "this will show up in the foo table, under the foo column"})

	if err != nil {
		log.Fatalln(err)
	}
	fmt.Println(result.Status)
*/
type Client struct {
	// The workspace to send logs to
	WorkspaceID string

	// The secret used to authenticate
	SharedKey string

	// The custom logs table
	CustomTable string

	// Allows you to specify a custom http.Client
	Client http.Client
}

// Send a log entry to Log Analytics
func (c *Client) Log(object any) (*http.Response, error) {
	msdate := formatDate(time.Now())
	body, err := json.Marshal(object)
	if err != nil {
		return nil, fmt.Errorf("Failed to convert object to json: %v", err)
	}

	req, err := c.buildRequest(bytes.NewReader(body), msdate)
	if err != nil {
		return nil, err
	}

	req.Header.Add("Authorization", c.buildAuth(len(body), msdate))
	result, err := c.Client.Do(req)
	return result, err
}

func buildSig(length int, msdate string) string {
	return fmt.Sprintf("POST\n%d\napplication/json\nx-ms-date:%s\n/api/logs", length, msdate)
}

func digest(keyStr string, text string) string {
	key, err := base64.StdEncoding.DecodeString(keyStr)
	if err != nil {
		panic(err)
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(text))

	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

func formatDate(t time.Time) string {
	return strings.ReplaceAll(t.UTC().Format(time.RFC1123), "UTC", "GMT")
}

func (c *Client) buildRequest(body io.Reader, msdate string) (*http.Request, error) {
	uri := fmt.Sprintf("https://%s.%s%s?api-version=%s",
		c.WorkspaceID,
		"ods.opinsights.azure.com",
		"/api/logs",
		"2016-04-01")
	req, err := http.NewRequest("POST", uri, body)
	if err != nil {
		return nil, fmt.Errorf("Unable to build request: %v", err)
	}

	// Basic headers
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Log-Type", c.CustomTable)
	req.Header.Add("x-ms-date", msdate)

	return req, nil
}

func (c *Client) buildAuth(contentLength int, msdate string) string {
	unencodedSig := buildSig(contentLength, msdate)
	sig := digest(c.SharedKey, unencodedSig)

	return fmt.Sprintf("SharedKey %s:%s", c.WorkspaceID, sig)
}
