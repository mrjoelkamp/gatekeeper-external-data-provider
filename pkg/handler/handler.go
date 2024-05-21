package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"path/filepath"

	"github.com/docker/attest/pkg/attest"
	"github.com/docker/attest/pkg/oci"
	"github.com/docker/attest/pkg/policy"
	"github.com/docker/attest/pkg/tuf"
	"github.com/open-policy-agent/frameworks/constraint/pkg/externaldata"
	"github.com/open-policy-agent/gatekeeper-external-data-provider/internal/embed"
	"github.com/open-policy-agent/gatekeeper-external-data-provider/pkg/utils"
	"k8s.io/klog/v2"
)

func Handler(w http.ResponseWriter, req *http.Request) {
	// only accept POST requests
	if req.Method != http.MethodPost {
		utils.SendResponse(nil, "only POST is allowed", w)
		return
	}

	// read request body
	requestBody, err := io.ReadAll(req.Body)
	if err != nil {
		utils.SendResponse(nil, fmt.Sprintf("unable to read request body: %v", err), w)
		return
	}

	klog.InfoS("received request", "body", requestBody)

	// parse request body
	var providerRequest externaldata.ProviderRequest
	err = json.Unmarshal(requestBody, &providerRequest)
	if err != nil {
		utils.SendResponse(nil, fmt.Sprintf("unable to unmarshal request body: %v", err), w)
		return
	}

	results := make([]externaldata.Item, 0)

	// create a tuf client
	tufOutputPath := filepath.Join("/tuf_temp", ".docker", "tuf")
	tufClient, err := createTufClient(tufOutputPath)
	if err != nil {
		utils.SendResponse(nil, err.Error(), w)
	}

	// iterate over all keys
	for _, key := range providerRequest.Request.Keys {
		// create a resolver for remote attestations
		platform := "linux/amd64"
		resolver := &oci.RegistryResolver{
			Image:    key,      // path to image index in OCI registry containing image attestations
			Platform: platform, // platform of subject image (image that attestations are being verified against)
		}

		// configure policy options
		opts := &policy.PolicyOptions{
			TufClient:       tufClient,
			LocalTargetsDir: filepath.Join("/tuf_temp", ".docker", "policy"), // location to store policy files downloaded from TUF
			LocalPolicyDir:  "",                                              // overrides TUF policy for local policy files if set
		}

		// verify attestations
		ctx := context.TODO()
		debug := true
		ctx = policy.WithPolicyEvaluator(ctx, policy.NewRegoEvaluator(debug))
		policy, err := attest.Verify(ctx, opts, resolver)
		if err != nil {
			results = append(results, externaldata.Item{
				Key:   key,
				Error: "admit: false, error: " + err.Error(),
			})
			continue
		}
		if policy {
			klog.Infof("policy passed: %v\n", policy)
			// valid key will have "_valid" appended as return value
			results = append(results, externaldata.Item{
				Key:   key,
				Value: "admit: true, message: policy passed",
			})
			continue // passed policy
		}
		// no policy found for image
		klog.Infof("no policy for image")
		results = append(results, externaldata.Item{
			Key:   key,
			Value: "admit: true, message: no policy",
		})
	}
	utils.SendResponse(&results, "", w)
}

func createTufClient(outputPath string) (*tuf.TufClient, error) {
	// using oci tuf metadata and targets
	metadataURI := "registry-1.docker.io/docker/tuf-metadata:latest"
	targetsURI := "registry-1.docker.io/docker/tuf-targets"
	// example using http tuf metadata and targets
	// metadataURI := "https://docker.github.io/tuf-staging/metadata"
	// targetsURI := "https://docker.github.io/tuf-staging/targets"

	return tuf.NewTufClient(embed.StagingRoot, outputPath, metadataURI, targetsURI)
}
