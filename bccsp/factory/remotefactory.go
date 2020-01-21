// +build pkcs11

/*
Copyright IBM Corp. 2016 All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

		 http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package factory

import (
	"github.com/hyperledger/fabric/bccsp"
	"github.com/hyperledger/fabric/bccsp/remote"
	"github.com/hyperledger/fabric/bccsp/sw"
	"github.com/pkg/errors"
)

const (
	// PKCS11BasedFactoryName is the name of the factory of the hsm-based BCCSP implementation
	REMOTEBasedFactoryName = "REMOTE"
)

// PKCS11Factory is the factory of the HSM-based BCCSP.
type REMOTEFactory struct{}

// Name returns the name of this factory
func (f *REMOTEFactory) Name() string {
	return REMOTEBasedFactoryName
}

// Get returns an instance of BCCSP using Opts.
func (f *REMOTEFactory) Get(config *FactoryOpts) (bccsp.BCCSP, error) {
	// Validate arguments
	if config == nil || config.RemoteOpts == nil {
		return nil, errors.New("Invalid config. It must not be nil.")
	}

	remoteOpts := config.RemoteOpts

	//TODO: PKCS11 does not need a keystore, but we have not migrated all of PKCS11 BCCSP to PKCS11 yet
	var ks bccsp.KeyStore
	// if remoteOpts.Ephemeral == true {
	// 	ks = sw.NewDummyKeyStore()
	// } else if remoteOpts.FileKeystore != nil {
	// 	fks, err := sw.NewFileBasedKeyStore(nil, p11Opts.FileKeystore.KeyStorePath, false)
	// 	if err != nil {
	// 		return nil, errors.Wrapf(err, "Failed to initialize software key store")
	// 	}
	// 	ks = fks
	// } else {
	// 	// Default to DummyKeystore
	ks = sw.NewDummyKeyStore()
	// }
	return remote.New(*remoteOpts, ks)
}
