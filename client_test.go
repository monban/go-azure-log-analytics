package loganalytics

import (
	"strings"
	"testing"
	"time"

	"github.com/matryer/is"
)

func TestBuildAuth(t *testing.T) {
	is := is.New(t)
	d := formatDate(time.Unix(1650736224, 0))
	c := Client{
		SharedKey:   "YQ==",
		WorkspaceID: "foo",
	}

	is.Equal(c.buildAuth(5, d), "SharedKey foo:bCb0SZxY5Lj4iXTc2Gket7lCEpDOll6ojz1loixpol4=")
}

func TestBuildRequest(t *testing.T) {
	is := is.New(t)

	c := Client{
		SharedKey:   "YQ==",
		WorkspaceID: "foo",
	}

	d := formatDate(time.Now())
	bodyStr := "test body"
	body := strings.NewReader(bodyStr)
	req := c.buildRequest(body, d)
	is.Equal(req.ContentLength, int64(len(bodyStr)))
	is.Equal(req.Header.Get("Content-Type"), "application/json")
}
