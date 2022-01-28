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
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"os"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/pkg/errors"
	"github.com/sigstore/cosign/cmd/cosign/cli/fulcio"
	"github.com/sigstore/cosign/cmd/cosign/cli/fulcio/fulcioverifier"
	"github.com/sigstore/fulcio/pkg/api"
	"github.com/sirupsen/logrus"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/sigstore/cosign/cmd/cosign/cli/options"
	cosigns "github.com/sigstore/cosign/cmd/cosign/cli/sign"
	"github.com/sigstore/cosign/pkg/cosign"
	"github.com/sigstore/cosign/pkg/oci"
	ociempty "github.com/sigstore/cosign/pkg/oci/empty"
	"github.com/sigstore/cosign/pkg/oci/mutate"
	ociremote "github.com/sigstore/cosign/pkg/oci/remote"
	"github.com/sigstore/cosign/pkg/oci/walk"
	"github.com/sigstore/cosign/pkg/providers"
	"github.com/sigstore/sigstore/pkg/oauthflow"
	"github.com/sigstore/sigstore/pkg/signature"
	sigPayload "github.com/sigstore/sigstore/pkg/signature/payload"
)

type defaultImpl struct{}

//go:generate go run github.com/maxbrunsfeld/counterfeiter/v6 -generate
//counterfeiter:generate . impl
type impl interface {
	VerifyImageInternal(*Signer, string) (*SignedImage, error)
	SignImageInternal(*Signer, string) (*SignedImage, error)
	keylessSigner(context.Context, cosigns.KeyOpts) (*cosigns.SignerVerifier, error)
}

func (*defaultImpl) VerifyImageInternal(signer *Signer, reference string) (*SignedImage, error) {
	return signer.VerifyImage(reference)
}

func regClientOpts(ctx context.Context) ([]ociremote.Option, error) {

	ropts := []remote.Option{
		remote.WithContext(ctx),
		remote.WithUserAgent("k8s-releng-sdk"),
	}

	//https://github.com/sigstore/cosign/blob/main/cmd/cosign/cli/options/registry.go#L22
	// Aqui pelé lo de k8s
	ropts = append(ropts, remote.WithAuthFromKeychain(authn.DefaultKeychain))
	/*

		if o != nil && o.AllowInsecure {
			opts = append(opts, remote.WithTransport(&http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}})) // #nosec G402
		}
		return opts
	*/

	opts := []ociremote.Option{ociremote.WithRemoteOptions(ropts...)}
	/*
		if o.RefOpts.TagPrefix != "" {
			opts = append(opts, ociremote.WithPrefix(o.RefOpts.TagPrefix))
		}
	*/
	targetRepoOverride, err := ociremote.GetEnvTargetRepository()
	if err != nil {
		return nil, err
	}
	if (targetRepoOverride != name.Repository{}) {
		opts = append(opts, ociremote.WithTargetRepository(targetRepoOverride))
	}
	return opts, nil
}

// SignImageInternal signs an image and returns the resulting singed image object
func (impl *defaultImpl) SignImageInternal(signer *Signer, referenceName string) (*SignedImage, error) {
	ctx := context.Background()
	ko := cosigns.KeyOpts{
		// KeyRef: signer.options.o.Key,
		// PassFunc:                 generate.GetPass,
		Sk:                       false,
		Slot:                     "",
		FulcioURL:                "https://v1.fulcio.sigstore.dev",
		IDToken:                  "",
		InsecureSkipFulcioVerify: false,
		RekorURL:                 "https://rekor.sigstore.dev",
		OIDCIssuer:               "https://oauth2.sigstore.dev/auth",
		OIDCClientID:             "sigstore",
		OIDCClientSecret:         "",
	}

	keyless, err := impl.keylessSigner(ctx, ko)
	if err != nil {
		return nil, errors.Wrap(err, "getting signer")
	}

	ref, err := name.ParseReference(referenceName)
	if err != nil {
		return nil, errors.Wrap(err, "parsing reference")
	}
	//opts, err := regOpts.ClientOpts(ctx)
	opts, err := regClientOpts(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "constructing client options")
	}

	if digest, ok := ref.(name.Digest); ok && !recursive {
		se, err := ociempty.SignedImage(ref)
		if err != nil {
			return nil, errors.Wrap(err, "accessing image")
		}
		err = signDigest(ctx, digest, ko, regOpts, annotations, upload, outputSignature, outputCertificate, force, recursive, dd, keyless, se)
		if err != nil {
			return nil, errors.Wrap(err, "signing digest")
		}
		continue
	}

	se, err := ociremote.SignedEntity(ref, opts...)
	if err != nil {
		return nil, errors.Wrap(err, "accessing entity")
	}

	if err := walk.SignedEntity(ctx, se, func(ctx context.Context, se oci.SignedEntity) error {
		// Get the digest for this entity in our walk.
		d, err := se.(interface{ Digest() (v1.Hash, error) }).Digest()
		if err != nil {
			return errors.Wrap(err, "computing digest")
		}
		digest := ref.Context().Digest(d.String())

		err = signDigest(ctx, digest, ko, regOpts, annotations, upload, outputSignature, outputCertificate, force, recursive, dd, keyless, se)
		if err != nil {
			return errors.Wrap(err, "signing digest")
		}
		return nil, ErrDone
	}); err != nil {
		return nil, errors.Wrap(err, "recursively signing")
	}

	return &SignedImage{}, nil
}

func (impl *defaultImpl) keylessSigner(ctx context.Context, ko cosigns.KeyOpts) (*cosigns.SignerVerifier, error) {
	fClient, err := fulcio.NewClient(ko.FulcioURL)
	if err != nil {
		return nil, errors.Wrap(err, "creating Fulcio client")
	}
	tok := ko.IDToken
	if providers.Enabled(ctx) {
		tok, err = providers.Provide(ctx, "sigstore")
		if err != nil {
			return nil, errors.Wrap(err, "fetching ambient OIDC credentials")
		}
	}

	var k *fulcio.Signer

	fulcioSigner

	if ko.InsecureSkipFulcioVerify {
		if k, err = fulcio.NewSigner(ctx, tok, ko.OIDCIssuer, ko.OIDCClientID, ko.OIDCClientSecret, fClient); err != nil {
			return nil, errors.Wrap(err, "getting key from Fulcio")
		}
	} else {
		if k, err = fulcioverifier.NewSigner(ctx, tok, ko.OIDCIssuer, ko.OIDCClientID, ko.OIDCClientSecret, fClient); err != nil {
			return nil, errors.Wrap(err, "getting key from Fulcio")
		}
	}

	return &cosigns.SignerVerifier{
		Cert:           k.Cert,
		Chain:          k.Chain,
		SignerVerifier: k,
	}, nil
}

func signDigest(
	ctx context.Context, digest name.Digest, ko cosigns.KeyOpts,
	regOpts options.RegistryOptions, annotations map[string]interface{},
	upload bool, outputSignature, outputCertificate string, force bool, recursive bool,
	dd mutate.DupeDetector, signerVerifier *cosigns.SignerVerifier, signedEnt oci.SignedEntity) error {

	var err error
	payload, err := (&sigPayload.Cosign{
		Image:       digest,
		Annotations: annotations,
	}).MarshalJSON()
	if err != nil {
		return errors.Wrap(err, "marshaling payload")
	}
	cosigner := NewCosigner(signerVerifier)

	// s = ipayload.NewSigner(signerVerifier)
	if signerVerifier.Cert != nil {
		// s = ifulcio.NewSigner(s, signerVerifier.Cert, signerVerifier.Chain)
		logrus.Fatal("Necesitas el signer de fulcio")
	}

	/*
		// TODO transparency log
		if ShouldUploadToTlog(ctx, digest, force, ko.RekorURL) {
			rClient, err := rekor.NewClient(ko.RekorURL)
			if err != nil {
				return err
			}
			s = irekor.NewSigner(s, rClient)
		}
	*/

	ociSig, _, err := cosigner.Sign(ctx, bytes.NewReader(payload))
	if err != nil {
		return err
	}

	b64sig, err := ociSig.Base64Signature()
	if err != nil {
		return err
	}

	if outputSignature != "" {
		// Add digest to suffix to differentiate each image during recursive signing
		if recursive {
			outputSignature = fmt.Sprintf("%s-%s", outputSignature, strings.Replace(digest.DigestStr(), ":", "-", 1))
		}
		if err := os.WriteFile(outputSignature, []byte(b64sig), 0600); err != nil {
			return errors.Wrap(err, "create signature file")
		}
	}

	if outputCertificate != "" {
		rekorBytes, err := signerVerifier.Bytes(ctx)
		if err != nil {
			return errors.Wrap(err, "create certificate file")
		}

		if err := os.WriteFile(outputCertificate, rekorBytes, 0600); err != nil {
			return errors.Wrap(err, "create certificate file")
		}
		// TODO: maybe accept a --b64 flag as well?
		fmt.Printf("Certificate wrote in the file %s\n", outputCertificate)
	}

	if !upload {
		return nil
	}

	// Attach the signature to the entity.
	newSE, err := mutate.AttachSignatureToEntity(signedEnt, ociSig, mutate.WithDupeDetector(dd))
	if err != nil {
		return err
	}

	// Publish the signatures associated with this entity
	walkOpts, err := regOpts.ClientOpts(ctx)
	if err != nil {
		return errors.Wrap(err, "constructing client options")
	}

	// Check if we are overriding the signatures repository location
	repo, _ := ociremote.GetEnvTargetRepository()
	if repo.RepositoryStr() == "" {
		fmt.Fprintln(os.Stderr, "Pushing signature to:", digest.Repository)
	} else {
		fmt.Fprintln(os.Stderr, "Pushing signature to:", repo.RepositoryStr())
	}

	// Publish the signatures associated with this entity
	if err := ociremote.WriteSignatures(digest.Repository, newSE, walkOpts...); err != nil {
		return err
	}

	return nil
}

type FulcioSignerVerifier struct {
	Cert  []byte
	Chain []byte
	SCT   []byte
	pub   *ecdsa.PublicKey
	*signature.ECDSASignerVerifier
}

// Este necesita IDToken
func fulcioSignerVerifier() (*FulcioSignerVerifier, error) {
	// Generate a private key:
	priv, err := cosign.GeneratePrivateKey()
	if err != nil {
		return nil, errors.Wrap(err, "generating cert")
	}
	signer, err := signature.LoadECDSASignerVerifier(priv, crypto.SHA256)
	if err != nil {
		return nil, err
	}
	fmt.Fprintln(os.Stderr, "Retrieving signed certificate...")

	//Resp, err := GetCert(ctx, priv, idToken, flow, oidcIssuer, oidcClientID, oidcClientSecret, fClient) // TODO, use the chain.
	//if err != nil {
	//	return nil, errors.Wrap(err, "retrieving cert")
	//}

	&oauthflow.StaticTokenGetter{RawToken: idToken}

	pubBytes, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return nil, err
	}

	tok, err := connector.OIDConnect(oidcIssuer, oidcClientID, oidcClientSecret)
	if err != nil {
		return nil, err
	}

	// Sign the email address as part of the request
	h := sha256.Sum256([]byte(tok.Subject))
	proof, err := ecdsa.SignASN1(rand.Reader, priv, h[:])
	if err != nil {
		return nil, err
	}

	cr := api.CertificateRequest{
		PublicKey: api.Key{
			Algorithm: "ecdsa",
			Content:   pubBytes,
		},
		SignedEmailAddress: proof,
	}

	return fc.SigningCert(cr, tok.RawString)

	f := &FulcioSignerVerifier{
		pub:                 &priv.PublicKey,
		ECDSASignerVerifier: signer,
		Cert:                Resp.CertPEM,
		Chain:               Resp.ChainPEM,
		SCT:                 Resp.SCT,
	}

	return f, nil
}
