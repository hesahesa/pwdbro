package checker

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/pkg/errors"
)

// Pwnedpasswords is a checker struct that will call pwnedpasswords API
// to determine if a password is within the database of leaked password
// or not
type Pwnedpasswords struct {
	// HTTPClient is the http.Client that is being used to make an API call
	HTTPClient *http.Client
}

const baseURL = "https://api.pwnedpasswords.com/range/"

var (
	// ErrStringEmpty is an error if the string is an empty string
	ErrStringEmpty = errors.New("Empty password string error")
	// ErrNonHTTPOk is an error if the resulting HTTP call to the API is non 200 OK
	ErrNonHTTPOk = errors.New("Non HTTP OK in API Call")
)

// MethodName returns the method name of the checker
func (pp *Pwnedpasswords) MethodName() string {
	return "pwnedpasswords API"
}

// CheckPassword will call pwnedpasswords API to determine if a supplied
// password is in the database of password leak or not.
// The supplied password is NOT being sent to the pwnedpasswords API, instead
// only the SHA1 prefix (5 first hash char) is sent, this ensures that
// the pwnedpasswords API doesn't know the password that is being sent
// (it is protected in k-anonymity guarantee).
// Refer to https://haveibeenpwned.com/API/v3#PwnedPasswords for more details.
func (pp *Pwnedpasswords) CheckPassword(pwd string) (bool, string, error) {
	// error if rune count is 0 (or less ?)
	if utf8.RuneCountInString(pwd) <= 0 {
		return false, "", ErrStringEmpty
	}

	// construct a new http.Client if not already supplied
	if pp.HTTPClient == nil {
		pp.HTTPClient = &http.Client{
			Timeout: 5 * time.Second,
		}
	}

	// compute sha1
	data := []byte(pwd)
	hash := sha1.Sum(data)

	// get prefix suffix
	hex := strings.ToUpper(hex.EncodeToString(hash[0:]))
	prefix := hex[0:5]
	suffix := hex[5:]

	// hit the API
	fullURL := baseURL + prefix
	req, err := http.NewRequest("GET", fullURL, nil)
	if err != nil {
		return false, "", errors.Wrap(err, "fail in creating new http request")
	}

	// be a friendly client and tell the API who are you
	req.Header.Set("User-Agent", "github.com/hesahesa/pwdbro")

	resp, err := pp.HTTPClient.Do(req)
	if err != nil {
		return false, "", errors.Wrap(err, "http api call failure")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false, "", ErrNonHTTPOk
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return false, "", errors.Wrap(err, "fail in reading response body")
	}

	// check suffix in response body
	lines := strings.Split(string(body), "\n")
	for _, line := range lines {
		tokens := strings.Split(line, ":")
		// if it matches with the API response, return as not safe
		if suffix == tokens[0] {
			occurence := string(tokens[1])
			return false, fmt.Sprintf("shows in pwnedpasswords with occurence: %s", occurence), nil
		}
	}

	// if the suffix doesn't match with any API response data, return as safe
	return true, "", nil
}
