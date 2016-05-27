package model

import (
	"gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"
)

type Crl struct {
	CaName string `bson:"ca_name"`
	CrlPem string `bson:"crl_pem"`
}

type DataStore interface {
	FindCrlByCaName(caName string) (crl *Crl, err error)
	Copy() DataStore
	Close()
}

type dataStoreImpl struct {
	session  *mgo.Session
	database string
}

func InitDataStore(url string, database string) (DataStore, error) {
	session, err := mgo.Dial(url)
	if err != nil {
		return nil, err
	}
	return &dataStoreImpl{session, database}, nil
}

func (ds *dataStoreImpl) crlDB() *mgo.Database {
	return ds.session.DB(ds.database)
}

func (ds *dataStoreImpl) crlCollection() *mgo.Collection {
	return ds.crlDB().C("r509_mongoid_models_crls")
}

func (ds *dataStoreImpl) FindCrlByCaName(caName string) (crl *Crl, err error) {
	err = ds.crlCollection().Find(bson.M{"ca_name": caName}).One(&crl)
	return
}

func (ds *dataStoreImpl) Copy() DataStore {
	return &dataStoreImpl{ds.session.Copy(), ds.database}
}

func (ds *dataStoreImpl) Close() {
	if ds.session != nil {
		ds.session.Close()
	}
	return
}
