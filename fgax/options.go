package fgax

import (
	openfga "github.com/openfga/go-sdk"
	ofgaclient "github.com/openfga/go-sdk/client"
)

const (
	// HeaderXRequestID is the header name for request id
	HeaderXRequestID = "X-Request-Id"
)

// RequestOptions holds per-request options that can be applied to OpenFGA requests
type RequestOptions struct {
	// Headers holds custom headers to be sent with the request
	Headers map[string]string
	// Consistency holds the consistency preference for the request, defaults to MINIMUM_LATENCY
	Consistency *openfga.ConsistencyPreference
	// IgnoreDuplicateKeyError indicates whether to ignore duplicate key errors and missing deletes, defaults to true
	IgnoreDuplicateKeyError bool
}

// RequestOption is a functional option for RequestOptions
type RequestOption func(*RequestOptions)

// WithRequestIDHeader sets the X-Request-Id header for the request
func WithRequestIDHeader(id string) RequestOption {
	return func(ro *RequestOptions) {
		if ro.Headers == nil {
			ro.Headers = map[string]string{}
		}

		ro.Headers[HeaderXRequestID] = id
	}
}

// WithCustomHeader sets a custom header for the request
func WithCustomHeader(header, value string) RequestOption {
	return func(ro *RequestOptions) {
		if ro.Headers == nil {
			ro.Headers = map[string]string{}
		}

		ro.Headers[header] = value
	}
}

// WithHighConsistency sets the consistency preference to higher consistency
func WithHighConsistency() RequestOption {
	return func(ro *RequestOptions) {
		c := openfga.CONSISTENCYPREFERENCE_HIGHER_CONSISTENCY
		ro.Consistency = &c
	}
}

// WithIgnoreDuplicateKeyError sets whether the client should ignore duplicate key errors and missing deletes
func WithIgnoreDuplicateKeyError(ignore bool) RequestOption {
	return func(ro *RequestOptions) {
		ro.IgnoreDuplicateKeyError = ignore
	}
}

// getRequestOptions aggregates functional RequestOptions into a RequestOptions struct
func getRequestOptions(opts ...RequestOption) RequestOptions {
	ro := RequestOptions{
		Consistency:             &defaultConsistency,
		IgnoreDuplicateKeyError: true,
	}

	for _, o := range opts {
		o(&ro)
	}

	return ro
}

// convert to ofgaclient.ClientCheckOptions
func getCheckOptions(opts ...RequestOption) ofgaclient.ClientCheckOptions {
	ro := getRequestOptions(opts...)

	o := ofgaclient.ClientCheckOptions{}

	o.Consistency = ro.Consistency

	if len(ro.Headers) > 0 {
		o.RequestOptions = ofgaclient.RequestOptions{Headers: ro.Headers}
	}

	return o
}

func getBatchCheckOptions(opts ...RequestOption) ofgaclient.BatchCheckOptions {
	ro := getRequestOptions(opts...)

	o := ofgaclient.BatchCheckOptions{
		MaxBatchSize:        &batchSizeLimit,
		MaxParallelRequests: &batchParallelLimit,
	}

	o.Consistency = ro.Consistency

	if len(ro.Headers) > 0 {
		o.RequestOptions = ofgaclient.RequestOptions{Headers: ro.Headers}
	}

	return o
}

func getReadOptions(opts ...RequestOption) ofgaclient.ClientReadOptions {
	ro := getRequestOptions(opts...)

	o := ofgaclient.ClientReadOptions{
		PageSize: openfga.PtrInt32(defaultPageSize),
	}

	o.Consistency = ro.Consistency

	if len(ro.Headers) > 0 {
		o.RequestOptions = ofgaclient.RequestOptions{Headers: ro.Headers}
	}

	return o
}

func getWriteOptions(opts ...RequestOption) ofgaclient.ClientWriteOptions {
	ro := getRequestOptions(opts...)

	o := ofgaclient.ClientWriteOptions{}

	if len(ro.Headers) > 0 {
		o.RequestOptions = ofgaclient.RequestOptions{Headers: ro.Headers}
	}

	// Set conflict options based on IgnoreDuplicateKeyError setting
	o.Conflict = ofgaclient.ClientWriteConflictOptions{
		OnDuplicateWrites: ofgaclient.CLIENT_WRITE_REQUEST_ON_DUPLICATE_WRITES_ERROR,
		OnMissingDeletes:  ofgaclient.CLIENT_WRITE_REQUEST_ON_MISSING_DELETES_ERROR,
	}

	if ro.IgnoreDuplicateKeyError {
		o.Conflict = ofgaclient.ClientWriteConflictOptions{
			OnDuplicateWrites: ofgaclient.CLIENT_WRITE_REQUEST_ON_DUPLICATE_WRITES_IGNORE,
			OnMissingDeletes:  ofgaclient.CLIENT_WRITE_REQUEST_ON_MISSING_DELETES_IGNORE,
		}
	}

	// write options do not support a consistency field in the SDK

	return o
}
