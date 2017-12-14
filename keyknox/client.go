package keyknox

import (
	"context"
	"net/http"
	"net/url"
	"strconv"

	"gopkg.in/virgil.v6/common"
)

type KeyknoxClient struct {
	Client     common.HttpClient
	ApiAddress string
}

type EvalReq struct {
	tweak       string
	blindedMsg  []byte
	InlineProof bool
	Version     int
}

func MakeEvalReq(tweak string, blindedMsg []byte) EvalReq {
	return EvalReq{
		tweak:      tweak,
		blindedMsg: blindedMsg,
	}
}

type Proof struct {
	P []byte `json:"p"`
	C []byte `json:"c"`
	U []byte `json:"u"`
}
type EvalResp struct {
	Result []byte
	Proof  *Proof
}

func (c *KeyknoxClient) Eval(req EvalReq) (EvalResp, error) {
	values := url.Values{}
	if req.InlineProof {
		values.Add("include", "proof")
	}
	if req.Version > 0 {
		values.Add("v", strconv.Itoa(req.Version))
	}
	var resp EvalResp
	err := c.getVirgilClient().Send(
		context.Background(),
		http.MethodPost,
		"/eval?"+values.Encode(),
		map[string]interface{}{
			"tweak":           req.tweak,
			"blinded_message": req.blindedMsg,
		},
		&resp,
	)
	return resp, err
}

type RotateKeyResp struct {
	Delta                    []byte `json:"delta"`
	NewP                     []byte `json:"new_p"`
	PreviousSecretKeyVersion int    `json:"previous_secret_key_version"`
}

func (c *KeyknoxClient) RotateKey() (RotateKeyResp, error) {
	var resp RotateKeyResp
	err := c.getVirgilClient().Send(
		context.Background(),
		http.MethodPost,
		"/rotate",
		nil,
		&resp,
	)
	return resp, err
}

func (c *KeyknoxClient) getVirgilClient() *common.VirgilHttpClient {
	var address = "https://api.virgilsecurity.com/keyknox/v1"
	var httpClient common.HttpClient = http.DefaultClient
	if c.ApiAddress != "" {
		address = c.ApiAddress
	}
	if c.Client != nil {
		httpClient = c.Client
	}
	return &common.VirgilHttpClient{
		Address: address,
		Client:  httpClient,
	}
}
