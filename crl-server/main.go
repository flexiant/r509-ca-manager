package main

import (
	"os"

	log "github.com/Sirupsen/logrus"
	"github.com/besol/r509-ca-manager/crl-server/handlers"
	"github.com/besol/r509-ca-manager/crl-server/model"
	"github.com/zenazn/goji"
)

var dataStore model.DataStore

const defaultMongoURL string = "mongodb://localhost"
const defaultDatabase string = "r509-ca-http-dev"

var mongoURL, database string

func main() {
	mongoURL = os.Getenv("CRL_SERVER_MONGO_URL")
	if mongoURL == "" {
		mongoURL = defaultMongoURL
	}
	database = os.Getenv("CRL_SERVER_MONGO_DATABASE")
	if database == "" {
		database = defaultDatabase
	}
	var err error
	dataStore, err = model.InitDataStore(mongoURL, database)
	if err != nil {
		log.Fatalf("Cannot connect to database %s at %s - %#v", database, mongoURL, err)
	}
	defer dataStore.Close()
	log.Printf("DataStore: %#v\n\n", dataStore)
	// r := web.New()
	//    r.Use(middleware.Logger)
	//    r.Use(middleware.Recoverer)

	//    r.Get("/crls/:caName.crl", serveCrl)

	//    graceful.ListenAndServeTLS(":8000", "cert.pem", "key.pem", r)
	goji.Get("/crls/:caName.crl", handlers.GetCRLHandler{dataStore})
	goji.Serve()
}
