/*
Copyright 2022 The Kubernetes Authors.

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

package sign

import (
	"context"
	"os"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/pkg/errors"
	"github.com/sigstore/cosign/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/cmd/cosign/cli/sign"
	"github.com/sigstore/cosign/cmd/cosign/cli/verify"
	"github.com/sigstore/cosign/pkg/oci"
	"github.com/sigstore/cosign/pkg/oci/remote"
	"github.com/sigstore/cosign/pkg/providers"
	"github.com/sirupsen/logrus"

	"sigs.k8s.io/release-utils/env"
	"sigs.k8s.io/release-utils/util"
)

type defaultImpl struct{}

//go:generate go run github.com/maxbrunsfeld/counterfeiter/v6 -generate
//counterfeiter:generate . impl
//go:generate /usr/bin/env bash -c "cat ../scripts/boilerplate/boilerplate.generatego.txt signfakes/fake_impl.go > signfakes/_fake_impl.go && mv signfakes/_fake_impl.go signfakes/fake_impl.go"
type impl interface {
	VerifyFileInternal(*Signer, string) (*SignedObject, error)
	VerifyImageInternal(ctx context.Context, keyPath string, images []string) (*SignedObject, error)
	SignImageInternal(ctx context.Context, ko sign.KeyOpts, regOpts options.RegistryOptions,
		annotations map[string]interface{}, imgs []string, certPath string, upload bool,
		outputSignature string, outputCertificate string, payloadPath string, force bool,
		recursive bool, attachment string) error
	Setenv(string, string) error
	EnvDefault(string, string) string
	TokenFromProviders(context.Context, *logrus.Logger) (string, error)
	FileExists(string) bool
	ParseReference(string, ...name.Option) (name.Reference, error)
	SignedEntity(name.Reference, ...remote.Option) (oci.SignedEntity, error)
	Signatures(oci.SignedEntity) (oci.Signatures, error)
	SignaturesList(oci.Signatures) ([]oci.Signature, error)
}

func (*defaultImpl) VerifyFileInternal(signer *Signer, path string) (*SignedObject, error) {
	return signer.VerifyFile(path)
}

func (*defaultImpl) VerifyImageInternal(ctx context.Context, publickeyPath string, images []string) (*SignedObject, error) {
	v := verify.VerifyCommand{KeyRef: publickeyPath}
	return &SignedObject{}, v.Exec(ctx, images)
}

func (*defaultImpl) SignImageInternal(ctx context.Context, ko sign.KeyOpts, regOpts options.RegistryOptions, // nolint: gocritic
	annotations map[string]interface{}, imgs []string, certPath string, upload bool,
	outputSignature string, outputCertificate string, payloadPath string, force bool,
	recursive bool, attachment string) error {
	return sign.SignCmd(
		ctx, ko, regOpts, annotations, imgs, certPath, upload, outputSignature,
		outputCertificate, payloadPath, force, recursive, attachment,
	)
}

func (*defaultImpl) Setenv(key, value string) error {
	return os.Setenv(key, value)
}

func (*defaultImpl) EnvDefault(key, def string) string {
	return env.Default(key, def)
}

// TokenFromProviders will try the cosign OIDC providers to get an
// oidc token from them.
func (d *defaultImpl) TokenFromProviders(ctx context.Context, logger *logrus.Logger) (string, error) {
	if !d.IdentityProvidersEnabled(ctx) {
		logger.Warn("No OIDC provider enabled. Token cannot be obtained autmatically.")
		return "", nil
	}

	tok, err := providers.Provide(ctx, "sigstore")
	if err != nil {
		return "", errors.Wrap(err, "fetching oidc token from environment")
	}
	return tok, nil
}

// FileExists returns true if a file exists
func (*defaultImpl) FileExists(path string) bool {
	return util.Exists(path)
}

// IdentityProvidersEnabled returns true if any of the cosign
// identity providers is able to obteain an OIDC identity token
// suitable for keyless signing,
func (*defaultImpl) IdentityProvidersEnabled(ctx context.Context) bool {
	return providers.Enabled(ctx)
}

func (*defaultImpl) ParseReference(
	s string, opts ...name.Option,
) (name.Reference, error) {
	return name.ParseReference(s, opts...)
}

func (*defaultImpl) SignedEntity(
	ref name.Reference, opts ...remote.Option,
) (oci.SignedEntity, error) {
	return remote.SignedEntity(ref, opts...)
}

func (*defaultImpl) Signatures(
	entity oci.SignedEntity,
) (oci.Signatures, error) {
	return entity.Signatures()
}

func (*defaultImpl) SignaturesList(
	signatures oci.Signatures,
) ([]oci.Signature, error) {
	return signatures.Get()
}
