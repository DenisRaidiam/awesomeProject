package main

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jws"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

func main() {

	client := getClient()

	signPair := getSigningPair()

	log.Print("Hello")

	resp, err := http.Get("https://data.directory.showcase.raidiam.io/participants")

	if err != nil {
		log.Print("Couldnt reach participants endpoint")
		panic("Couldnt reach participants endpoint")
	}

	body, err := io.ReadAll(resp.Body)

	if err != nil {
		log.Print("Couldnt read participants response")
		panic("Couldnt read participants response")
	}

	var participantsResponse = []Organisation{}

	if err = json.Unmarshal(body, &participantsResponse); err != nil {
		log.Print("Couldnt parse the participants response")
		log.Print(err.Error())
		panic("Couldnt parse the participants response")
	}

	servers := printAllServers(participantsResponse)

	selectedServer := selectServer(servers)

	fmt.Printf("Selected Server -> %s\n", selectedServer.OpenIDDiscoveryDocument)

	resp, err = http.Get(selectedServer.OpenIDDiscoveryDocument)

	if err != nil {
		log.Printf("Couldnt reach wellknown -> %s", selectedServer.OpenIDDiscoveryDocument)
		panic("Couldnt reach wellknown")
	}

	wellKnwonResponse := WellKnown{}

	wellKnownBody, err := io.ReadAll(resp.Body)

	if err != nil {
		log.Printf("Couldnt reach wellknown -> %s\n", selectedServer.OpenIDDiscoveryDocument)
		panic("Couldnt reach wellknown")
	}

	if err := json.Unmarshal(wellKnownBody, &wellKnwonResponse); err != nil {
		log.Printf("Couldnt parse the wellknown response")
		panic("Couldnt parse the wellknown response")
	}

	log.Printf("token endpoint -> %s", wellKnwonResponse.TokenEndpoint)

	//getAccessTokenCredentialsGrant(wellKnwonResponse.TokenEndpoint, client, signPair)

	getAccessTokenAuthorisationCode(wellKnwonResponse.TokenEndpoint, wellKnwonResponse.AuthorizationEndpoint, client, signPair)
}

func getSigningPair() tls.Certificate {
	signPair, err := tls.LoadX509KeyPair("certs/sign.pem", "certs/sign.key")

	if err != nil {
		log.Printf("Could not load signing key pair - %S", err.Error())
		panic("Could not load signing key pair")
	}

	return signPair
}

func getAccessTokenAuthorisationCode(tokenEndpoint string, authEndpoint string, client *http.Client, signPair tls.Certificate) {

	state, _ := randomBytesInHex(5)

	nonce, _ := randomBytesInHex(5)

	authCode := AuthorisationCode{
		Aud:          authEndpoint,
		Nbf:          123456,
		Scope:        "openid",
		Iss:          "2f56c40c-abf9-4104-bf36-66385d795c63",
		ResponseType: "code id_token",
		RedirectUri:  "https://denis.podberiozkin.com",
		State:        state,
		Exp:          time.Now().Add(5 * time.Minute).Unix(),
		Nonce:        nonce,
		ClientId:     "2f56c40c-abf9-4104-bf36-66385d795c63",
	}

	signedAuthCode := marshalAndSign(authCode, signPair)

	form := url.Values{}

	form.Add("request", string(signedAuthCode))
	form.Add("client_id", "2f56c40c-abf9-4104-bf36-66385d795c63")
	form.Add("redirect_uri", "https://denis.podberiozkin.com")
	form.Add("scope", "openid")
	form.Add("response_type", "code id_token")

	println(authEndpoint)
	resp, err := client.PostForm(authEndpoint, form)

	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	// Print response
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}
	for key, value := range resp.Header {
		fmt.Printf("key = %s, value = %s\n", key, value)
	}
	println(string(body))

}

func getAccessTokenCredentialsGrant(tokenEndpoint string, client *http.Client, signPair tls.Certificate) {

	// Send request
	randomString, err := randomBytesInHex(10)
	if err != nil {
		panic(err)
	}

	ssa := ClientAssertion{
		Iss: "2f56c40c-abf9-4104-bf36-66385d795c63",
		Aud: tokenEndpoint,
		Exp: time.Now().Add(5 * time.Minute).Unix(),
		Iat: time.Now().Unix(),
		Sub: "2f56c40c-abf9-4104-bf36-66385d795c63",
		Jti: randomString,
	}

	signedClientAssertion := marshalAndSign(ssa, signPair)

	form := url.Values{}
	form.Add("client_id", "2f56c40c-abf9-4104-bf36-66385d795c63")
	form.Add("grant_type", "client_credentials")
	form.Add("scope", "openid")
	assertion := string(signedClientAssertion)
	log.Printf("Client Assertion - %s\n", assertion)
	form.Add("client_assertion", assertion)
	form.Add("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")

	resp, err := client.PostForm(tokenEndpoint, form)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	// Print response
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}
	for key, value := range resp.Header {
		fmt.Printf("key = %s, value = %s\n", key, value)
	}
	println(string(body))

}

func marshalAndSign(structure interface{}, signPair tls.Certificate) []byte {
	b, err := json.Marshal(structure)

	if err != nil {
		log.Println("Could not marshal ssa")
		panic("Could not marshal ssa")
	}

	headers := jws.NewHeaders()

	err = headers.Set(jws.TypeKey, "JWT")
	err = headers.Set(jws.KeyIDKey, "sIBQwY_x4GL_RORDpwZShIvQ2Fzgg0VlzYV6W6q-BMc")

	if err != nil {
		panic("Couldnt add header")
	}

	signedClientAssertion, err := jws.Sign(b, jwa.PS256, signPair.PrivateKey, jws.WithHeaders(headers))
	return signedClientAssertion
}

func getClient() *http.Client {
	cert, err := tls.LoadX509KeyPair("certs/pem.pem", "certs/key.key")
	if err != nil {
		panic(err)
	}

	// Load CA cert
	caCert, err := ioutil.ReadFile("certs/ca.pem")
	if err != nil {
		panic(err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	// Create TLS config with the client certificates and CA
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caCertPool,
	}
	tlsConfig.BuildNameToCertificate()

	// Create transport with the TLS config
	transport := &http.Transport{TLSClientConfig: tlsConfig}

	// Create client with the transport
	client := &http.Client{Transport: transport}
	return client
}

func randomBytesInHex(count int) (string, error) {
	buf := make([]byte, count)
	_, err := io.ReadFull(rand.Reader, buf)
	if err != nil {
		return "", fmt.Errorf("Could not generate %d random bytes: %v", count, err)
	}

	return hex.EncodeToString(buf), nil
}

func selectServer(servers []AuthorisationServer) AuthorisationServer {
	println("Select a server:")

	var input string
	_, err := fmt.Scanln(&input)

	if err != nil {
		log.Print("Error reading input:", err)
		panic("Error reading input")

	}

	selectedServer, err := strconv.Atoi(input)

	if err != nil {
		log.Print("Couldnt parse user input:", err)
		panic("Couldnt parse user input:")
	}

	return servers[selectedServer-1]
}

func printAllServers(orgs []Organisation) []AuthorisationServer {
	var servers []AuthorisationServer
	println("Available servers")
	for _, org := range orgs {
		for i, server := range org.AuthorisationServers {
			fmt.Printf("%d) %s\n", i+1, server.CustomerFriendlyName)
			servers = append(servers, server)
		}
	}

	return servers
}
