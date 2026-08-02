// Package iproyal implements the IPRoyal residential proxy API client —
// /me, /access/entry-nodes, /residential-subusers, /access/countries.
//
// Auth header is implemented as "Authorization: Bearer <token>", the
// standard REST convention — IPRoyal's public OpenAPI docs don't state
// the exact header explicitly. NEEDS LIVE VERIFICATION against a real
// IPROYAL_API_TOKEN before this is trusted; if requests come back 401,
// this is the first thing to check.
//
// Responses are decoded into map[string]any / []map[string]any rather
// than strict typed structs: the OpenAPI schema component definitions
// for field names (traffic balance, subuser fields, etc.) weren't
// available at write time. Once verified against a real response, add
// typed structs on top of these.
package iproyal

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

const DefaultBaseURL = "https://resi-api.iproyal.com/v1"

type Client struct {
	BaseURL    string
	APIToken   string
	HTTPClient *http.Client
}

func NewClient(apiToken string) *Client {
	return &Client{
		BaseURL:    DefaultBaseURL,
		APIToken:   apiToken,
		HTTPClient: &http.Client{Timeout: 15 * time.Second},
	}
}

func (c *Client) do(ctx context.Context, method, path string, query url.Values, body any) (json.RawMessage, error) {
	u := c.BaseURL + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}

	var reqBody io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("iproyal: encode request body: %w", err)
		}
		reqBody = bytes.NewReader(b)
	}

	req, err := http.NewRequestWithContext(ctx, method, u, reqBody)
	if err != nil {
		return nil, fmt.Errorf("iproyal: build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.APIToken)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("iproyal: request %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("iproyal: read response body: %w", err)
	}

	if resp.StatusCode == http.StatusUnauthorized {
		return nil, fmt.Errorf("iproyal: 401 unauthorized on %s %s — check IPROYAL_API_TOKEN and the Authorization header format (currently \"Bearer <token>\", unverified against live API)", method, path)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("iproyal: %s %s returned %d: %s", method, path, resp.StatusCode, string(raw))
	}

	return raw, nil
}

// Me fetches GET /me (account-level residential user details, incl.
// traffic balance — deprecated alias for /residential/me per IPRoyal docs).
func (c *Client) Me(ctx context.Context) (map[string]any, error) {
	raw, err := c.do(ctx, http.MethodGet, "/me", nil, nil)
	if err != nil {
		return nil, err
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("iproyal: decode /me response: %w (raw: %s)", err, truncate(raw, 500))
	}
	return out, nil
}

// EntryNodes fetches GET /access/entry-nodes — a top-level JSON array of
// gateway entry nodes (DNS hostname + resolved IPv4), not wrapped in a
// "data" envelope.
func (c *Client) EntryNodes(ctx context.Context) ([]map[string]any, error) {
	raw, err := c.do(ctx, http.MethodGet, "/access/entry-nodes", nil, nil)
	if err != nil {
		return nil, err
	}
	var out []map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("iproyal: decode /access/entry-nodes response: %w (raw: %s)", err, truncate(raw, 500))
	}
	return out, nil
}

// SubuserListOptions controls pagination/filtering for ListSubusers.
type SubuserListOptions struct {
	Page    int
	PerPage int
	Search  string // 1-30 chars, filters by username
}

// ListSubusers fetches GET /residential-subusers (paginated collection).
func (c *Client) ListSubusers(ctx context.Context, opts SubuserListOptions) (map[string]any, error) {
	q := url.Values{}
	if opts.Page > 0 {
		q.Set("page", fmt.Sprint(opts.Page))
	}
	if opts.PerPage > 0 {
		q.Set("per_page", fmt.Sprint(opts.PerPage))
	}
	if opts.Search != "" {
		q.Set("search", opts.Search)
	}

	raw, err := c.do(ctx, http.MethodGet, "/residential-subusers", q, nil)
	if err != nil {
		return nil, err
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("iproyal: decode /residential-subusers response: %w (raw: %s)", err, truncate(raw, 500))
	}
	return out, nil
}

// CreateSubuserRequest is the POST /residential-subusers body. Field
// names are best-effort pending live schema verification.
type CreateSubuserRequest struct {
	Username       string  `json:"username"`
	Password       string  `json:"password"`
	TrafficLimitGB float64 `json:"traffic_limit_gb,omitempty"`
}

// CreateSubuser issues POST /residential-subusers.
func (c *Client) CreateSubuser(ctx context.Context, req CreateSubuserRequest) (map[string]any, error) {
	raw, err := c.do(ctx, http.MethodPost, "/residential-subusers", nil, req)
	if err != nil {
		return nil, err
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("iproyal: decode POST /residential-subusers response: %w (raw: %s)", err, truncate(raw, 500))
	}
	return out, nil
}

// Countries fetches GET /access/countries. poolType may be "" or "direct"
// (direct pool owners only, per IPRoyal docs).
func (c *Client) Countries(ctx context.Context, poolType string) (map[string]any, error) {
	q := url.Values{}
	if poolType != "" {
		q.Set("pool_type", poolType)
	}
	raw, err := c.do(ctx, http.MethodGet, "/access/countries", q, nil)
	if err != nil {
		return nil, err
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("iproyal: decode /access/countries response: %w (raw: %s)", err, truncate(raw, 500))
	}
	return out, nil
}

func truncate(b []byte, n int) string {
	if len(b) <= n {
		return string(b)
	}
	return string(b[:n]) + "...(truncated)"
}
