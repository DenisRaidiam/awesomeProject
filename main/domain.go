package main

type Organisation struct {
	OrganisationId       string                `json:"OrganisationId"`
	Status               string                `json:"Status"`
	OrganisationName     string                `json:"OrganisationName"`
	AuthorisationServers []AuthorisationServer `json:"AuthorisationServers"`
}

type AuthorisationServer struct {
	CustomerFriendlyName    string `json:"CustomerFriendlyName"`
	OpenIDDiscoveryDocument string `json:"OpenIDDiscoveryDocument"`
}

type WellKnown struct {
	TokenEndpoint         string `json:"token_endpoint"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
}
type ClientAssertion struct {
	Iss string `json:"iss"`
	Aud string `json:"aud"`
	Exp int64  `json:"exp"`
	Iat int64  `json:"iat"`
	Sub string `json:"sub"`
	Jti string `json:"jti"`
}

type AuthorisationCode struct {
	Aud          string `json:"aud"`
	Nbf          int    `json:"nbf"`
	Scope        string `json:"scope"`
	Iss          string `json:"iss"`
	ResponseType string `json:"response_type"`
	RedirectUri  string `json:"redirect_uri"`
	State        string `json:"state"`
	Exp          int64  `json:"exp"`
	Nonce        string `json:"nonce"`
	ClientId     string `json:"client_id"`
}
