// Purpose: This package provides functionality to manage Azure authentication records
package provider

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
)

func NewFile(appConfig string) (*File, error) {
	filename := filepath.Join(appConfig, "credentials.json")
	file, err := os.OpenFile(filename, os.O_CREATE, 0755)
	if err != nil {
		return nil, err
	}
	err = file.Close()
	if err != nil {
		return nil, err
	}
	return &File{filename: filename}, nil
}

type File struct {
	filename string
}

func (p *File) HasRecord() (bool, error) {
	rec, err := p.RetrieveRecord()
	return rec == azidentity.AuthenticationRecord{}, err
}

func (p *File) RetrieveRecord() (azidentity.AuthenticationRecord, error) {
	var record azidentity.AuthenticationRecord
	file, err := os.Open(p.filename)
	if err != nil {
		return record, err
	}
	defer file.Close()
	fd, err := file.Stat()
	if err != nil {
		return record, err
	}
	if fd.Size() == 0 {
		return record, nil
	}
	dec := json.NewDecoder(file)
	err = dec.Decode(&record)
	return record, err
}

func (p *File) StoreRecord(record azidentity.AuthenticationRecord) error {
	file, err := os.Create(p.filename)
	if err != nil {
		return err
	}
	defer file.Close()
	enc := json.NewEncoder(file)
	return enc.Encode(record)
}

func (p *File) ClearRecord() error {
	return os.Remove(p.filename)
}
