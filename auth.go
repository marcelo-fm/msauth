// Package msauth provides functionality to authenticate with Azure using Device Code flow.
package msauth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity/cache"
)

type RecordProvider interface {
	RetrieveRecord() (azidentity.AuthenticationRecord, error)
	StoreRecord(azidentity.AuthenticationRecord) error
	HasRecord() (bool, error)
}

func New(p RecordProvider, appName, clientID, tenantID string, scopes []string) (*Auth, error) {
	record, err := p.RetrieveRecord()
	if err != nil {
		return nil, err
	}
	cacheOpts := cache.Options{Name: appName}
	c, err := cache.New(&cacheOpts)
	if err != nil {
		return nil, err
	}
	if clientID == "" {
		return nil, errors.New("client id is not present")
	}
	if tenantID == "" {
		return nil, errors.New("tenant id is not defined")
	}
	opts := &azidentity.DeviceCodeCredentialOptions{
		ClientID:             clientID,
		TenantID:             tenantID,
		Cache:                c,
		AuthenticationRecord: record,
	}
	cred, err := azidentity.NewDeviceCodeCredential(opts)
	if err != nil {
		return nil, err
	}
	auth := &Auth{
		Record:     record,
		credential: cred,
		Scopes:     scopes,
		p:          p,
	}
	return auth, nil
}

type Auth struct {
	Record     azidentity.AuthenticationRecord
	credential *azidentity.DeviceCodeCredential
	p          RecordProvider
	Scopes     []string
}

func (a *Auth) Login() error {
	if a.Record == (azidentity.AuthenticationRecord{}) {
		return nil
	}
	rec, err := a.p.RetrieveRecord()
	if err == nil && rec != (azidentity.AuthenticationRecord{}) {
		a.Record = rec
		return nil
	}
	ctx, cancelFunc := context.WithTimeout(context.TODO(), 5*time.Minute)
	defer cancelFunc()
	rec, err = a.credential.Authenticate(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to authenticate: %w", err)
	}
	a.Record = rec
	err = a.p.StoreRecord(rec)
	if err != nil {
		return fmt.Errorf("failed to store authentication record: %w", err)
	}
	return nil
}

func (a *Auth) Logout() error {
	a.Record = azidentity.AuthenticationRecord{}
	return a.p.StoreRecord(a.Record)
}

func (a *Auth) Token(ctx context.Context) (azcore.AccessToken, error) {
	opts := policy.TokenRequestOptions{Scopes: a.Scopes, TenantID: a.Record.TenantID}
	return a.credential.GetToken(ctx, opts)
}
