package client

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"
	"encoding/json"
)

type safebrowsingClient struct {
	apiToken string
}

type SafeBrowsingRequest struct {
	Client SBRClient `json:"client"`
	ThreatInfo SBRThreatInfo `json:"threatInfo"`
}

type SBRClient struct {
	ClientID      string `json:"clientId"`
	ClientVersion string `json:"clientVersion"`
}

type SBRThreatEntry struct {
	URL string  `json:"url"`
}

type SBRThreatInfo struct {
	ThreatTypes      []string `json:"threatTypes"`
	PlatformTypes    []string `json:"platformTypes"`
	ThreatEntryTypes []string `json:"threatEntryTypes"`
	ThreatEntries 	 []SBRThreatEntry `json:"threatEntries"`
}


type SafeBrowsingResponse struct {
	Matches []struct {
		ThreatType      string `json:"threatType"`
		PlatformType    string `json:"platformType"`
		ThreatEntryType string `json:"threatEntryType"`
		Threat          struct {
			URL string `json:"url"`
		} `json:"threat"`
		ThreatEntryMetadata struct {
			Entries []struct {
				Key   string `json:"key"`
				Value string `json:"value"`
			} `json:"entries"`
		} `json:"threatEntryMetadata"`
		CacheDuration string `json:"cacheDuration"`
	} `json:"matches"`
}

type GoogleErrorResponse struct {
	Error struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
		Status  string `json:"status"`
		Details []struct {
			Type  string `json:"@type"`
			Links []struct {
				Description string `json:"description"`
				URL         string `json:"url"`
			} `json:"links"`
		} `json:"details"`
	} `json:"error"`
}

// NewSafeBrowsingClient return a "live" safebrowsing client
func NewSafeBrowsingClient(apiToken string) Client {
	return safebrowsingClient{
		apiToken,
	}
}

func (cli safebrowsingClient) CheckThreat(checkURL string) (bool, error) {
	requestBody := SafeBrowsingRequest{
		SBRClient{
			"gds-paas-safebrowsing",
			"0.0.1",
		},
		SBRThreatInfo{
			[]string{"MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"},
			[]string{"ANY_PLATFORM"},
			[]string{"URL"},
			[]SBRThreatEntry{
				{checkURL},
			},
		},
	}
	requestBodyBytes, err := json.Marshal(requestBody)
	if err != nil {
		return false, fmt.Errorf("Failed to Json unmarshal the body struct: %v", err)
	}
	req, err := http.NewRequest(http.MethodPost, "https://safebrowsing.googleapis.com/v4/threatMatches:find", bytes.NewBuffer(requestBodyBytes))

	q := req.URL.Query()
	q.Add("key", cli.apiToken)
	req.URL.RawQuery = q.Encode()
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false, fmt.Errorf("Failed to make request to Google Safe Browsing API: %s", resp.StatusCode)
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return false, fmt.Errorf("Failed to read response body: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		errorResponse := GoogleErrorResponse{}
		if err = json.Unmarshal(body, &errorResponse); err == nil {
			return false, fmt.Errorf("Safe Browsing API did not return 200. Error: %s (%s)", errorResponse.Error.Code, errorResponse.Error.Message)
		}
	}
	sbResponse := SafeBrowsingResponse{}
	if err = json.Unmarshal(body, &sbResponse); err != nil {
		return false, fmt.Errorf("Failed to unmarshal the Safe Browsing response: %v", err)
	}
	if len(sbResponse.Matches) == 0 {
		return false, nil
	}
	return true, nil
}
