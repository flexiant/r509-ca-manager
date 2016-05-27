package handlers

import (
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/besol/r509-ca-manager/crl-server/model"

	"github.com/zenazn/goji/web"
)

type GetCRLHandler struct {
	Datastore model.DataStore
}

func (h GetCRLHandler) ServeHTTPC(c web.C, w http.ResponseWriter, r *http.Request) {
	caName := c.URLParams["caName"]
	log.Printf("Fetching CRL for CA %s\n", caName)
	requestDataStore := h.Datastore.Copy()
	defer requestDataStore.Close()
	crl, err := requestDataStore.FindCrlByCaName(caName)
	if err != nil {
		reponseMessage := fmt.Sprintf("Could not find CRL for CA %s", caName)
		log.Println(reponseMessage)
		http.Error(w, reponseMessage, 404)
	} else {
		log.Printf("Serving CRL for CA %s", caName)
		decodedCRL, err := decodeCRL(crl)
		if err != nil {
			reponseMessage := fmt.Sprintf("Error while decoding CRL for %s to DER format: %#v", caName, err)
			log.Println(reponseMessage)
			http.Error(w, reponseMessage, 500)
		}
		w.Header().Set("Content-Type", "application/pkix-crl")
		w.Write(decodedCRL)
	}
}

func decodeCRL(crl *model.Crl) ([]byte, error) {
	reducedCrlPem := strings.Replace(strings.Replace(crl.CrlPem, "-----BEGIN X509 CRL-----\n", "", 1), "-----END X509 CRL-----\n", "", 1)
	return base64.StdEncoding.DecodeString(reducedCrlPem)
}
