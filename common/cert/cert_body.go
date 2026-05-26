package cert

type Certificate struct {
	ID        string `json:"id"`
	Issuer    string `json:"issuer"`
	PublicKey struct {
		N string `json:"n"`
		E string `json:"e"`
	} `json:"public_key"`
	Expire string `json:"expire"`
	Sign   string `json:"sign"`
}

type certBody struct {
	ID        string `json:"id"`
	Issuer    string `json:"issuer"`
	PublicKey struct {
		N string `json:"n"`
		E string `json:"e"`
	} `json:"public_key"`
	Expire string `json:"expire"`
}
