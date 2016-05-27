package handlers

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/besol/r509-ca-manager/crl-server/model"
	"github.com/zenazn/goji/web"
)

type mockDataStore struct {
	F func(caName string) (crl *model.Crl, err error)
}

func (m mockDataStore) Close() {
	// Do nothing
}

func (m mockDataStore) Copy() model.DataStore {
	return m
}

func (m mockDataStore) FindCrlByCaName(caName string) (crl *model.Crl, err error) {
	return m.F(caName)
}

func init() {
	log.SetOutput(ioutil.Discard)
}

func TestSuccess(t *testing.T) {
	crlDouble := model.Crl{
		CaName: "MyCAName",
		CrlPem: "-----BEGIN X509 CRL-----\nMTIzNDU2Nzg5\n-----END X509 CRL-----\n",
	}
	var store model.DataStore = mockDataStore{
		F: func(caName string) (crl *model.Crl, err error) {
			return &crlDouble, nil
		},
	}

	// build goji web context
	params := map[string]string{"caName": "MyCAName"}
	c := web.C{URLParams: params, Env: nil}

	// build request
	req, err := http.NewRequest("GET", "/crls/MyCAName.crl", nil)
	if err != nil {
		t.Fatal(err)
	}

	// build response recorder
	rr := httptest.NewRecorder()

	handler := GetCRLHandler{store}
	handler.ServeHTTPC(c, rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("returned wrong status code: got '%v' want '%v'", rr.Code, http.StatusOK)
	}

	expectedResponseBody := "123456789"
	if rr.Body.String() != expectedResponseBody {
		t.Errorf("returned wrong body: got '%v' want '%v'", rr.Body.String(), expectedResponseBody)
	}

	if contentType := rr.HeaderMap.Get("Content-Type"); contentType != "application/pkix-crl" {
		t.Errorf("returned wrong body: got '%v' want '%v'", contentType, "application/pkix-crl")
	}
}

func TestCANotFound(t *testing.T) {
	var store model.DataStore = mockDataStore{
		F: func(caName string) (crl *model.Crl, err error) {
			return nil, fmt.Errorf("Some error")
		},
	}

	// build goji web context
	params := map[string]string{"caName": "MyCAName"}
	c := web.C{URLParams: params, Env: nil}

	// build request
	req, err := http.NewRequest("GET", "/crls/MyCAName.crl", nil)
	if err != nil {
		t.Fatal(err)
	}

	// build response recorder
	rr := httptest.NewRecorder()

	handler := GetCRLHandler{store}
	handler.ServeHTTPC(c, rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("returned wrong status code: got '%v' want '%v'", rr.Code, http.StatusNotFound)
	}
}

func TestErrorDecoding(t *testing.T) {
	crlDouble := model.Crl{
		CaName: "MyCAName",
		CrlPem: "12345",
	}
	var store model.DataStore = mockDataStore{
		F: func(caName string) (crl *model.Crl, err error) {
			return &crlDouble, nil
		},
	}

	// build goji web context
	params := map[string]string{"caName": "MyCAName"}
	c := web.C{URLParams: params, Env: nil}

	// build request
	req, err := http.NewRequest("GET", "/crls/MyCAName.crl", nil)
	if err != nil {
		t.Fatal(err)
	}

	// build response recorder
	rr := httptest.NewRecorder()

	handler := GetCRLHandler{store}
	handler.ServeHTTPC(c, rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("returned wrong status code: got '%v' want '%v'", rr.Code, http.StatusInternalServerError)
	}
}
