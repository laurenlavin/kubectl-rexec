package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/mux"
	admissionv1 "k8s.io/api/admission/v1"
	authv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// --- helpers ---

func postExecHandler(t *testing.T, ar admissionv1.AdmissionReview, contentType string) (rr *httptest.ResponseRecorder, got admissionv1.AdmissionReview) {
	t.Helper()

	body, err := json.Marshal(ar)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/validate-exec", bytes.NewReader(body))
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	rr = httptest.NewRecorder()

	execHandler(rr, req)

	if rr.Code == http.StatusOK {
		if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
			t.Fatalf("unmarshal response: %v\nbody: %s", err, rr.Body.String())
		}
	}
	return rr, got
}

// --- execHandler tests ---

func TestExecHandlerUnsupportedContentType(t *testing.T) {
	rr, _ := postExecHandler(t, admissionv1.AdmissionReview{}, "text/plain")
	if rr.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusUnsupportedMediaType)
	}
}

func TestExecHandlerBadJSON(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/validate-exec", bytes.NewReader([]byte("{bad-json")))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	execHandler(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusBadRequest)
	}
}

func TestExecHandlerAllowsNonExecKinds(t *testing.T) {
	ar := admissionv1.AdmissionReview{
		Request: &admissionv1.AdmissionRequest{
			UID:  "123",
			Kind: metav1.GroupVersionKind{Kind: "Not-PodExecOptions"},
		},
	}
	rr, parsed := postExecHandler(t, ar, "application/json")
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", rr.Code, http.StatusOK, rr.Body.String())
	}
	if parsed.Response == nil || !parsed.Response.Allowed {
		t.Fatalf("expected Allowed=true for non-PodExecOptions, got: %+v", parsed.Response)
	}
}

func TestExecHandlerBypassedUser(t *testing.T) {
	oldBypass := ByPassedUsers
	t.Cleanup(func() { ByPassedUsers = oldBypass })

	ByPassedUsers = []string{"lauren"}

	ar := admissionv1.AdmissionReview{
		Request: &admissionv1.AdmissionRequest{
			UID: "u1",
			Kind: metav1.GroupVersionKind{
				Kind: "PodExecOptions",
			},
			UserInfo: authv1.UserInfo{
				Username: "lauren",
			},
		},
	}

	rr, parsed := postExecHandler(t, ar, "application/json")
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", rr.Code, http.StatusOK, rr.Body.String())
	}
	if parsed.Response == nil || !parsed.Response.Allowed {
		t.Fatalf("expected Allowed=true via ByPassedUsers, got: %+v", parsed.Response)
	}
}

func TestExecHandlerSecretSauce(t *testing.T) {
	oldBypass := ByPassedUsers
	oldSauce := SecretSauce
	t.Cleanup(func() {
		ByPassedUsers = oldBypass
		SecretSauce = oldSauce
	})

	ByPassedUsers = nil
	SecretSauce = "the-right-sauce"

	ar := admissionv1.AdmissionReview{
		Request: &admissionv1.AdmissionRequest{
			UID:  "u2",
			Kind: metav1.GroupVersionKind{Kind: "PodExecOptions"},
			UserInfo: authv1.UserInfo{
				Username: "lauren",
				Extra: map[string]authv1.ExtraValue{
					"secret-sauce": {"the-right-sauce"},
				},
			},
		},
	}

	rr, parsed := postExecHandler(t, ar, "application/json")
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", rr.Code, http.StatusOK, rr.Body.String())
	}
	if parsed.Response == nil || !parsed.Response.Allowed {
		t.Fatalf("expected Allowed=true via secret-sauce, got: %+v", parsed.Response)
	}
}

func TestExecHandlerExecDenied(t *testing.T) {
	oldBypass := ByPassedUsers
	oldSauce := SecretSauce
	t.Cleanup(func() {
		ByPassedUsers = oldBypass
		SecretSauce = oldSauce
	})

	ByPassedUsers = nil
	SecretSauce = "the-right-sauce"

	ar := admissionv1.AdmissionReview{
		Request: &admissionv1.AdmissionRequest{
			UID:  "u3",
			Kind: metav1.GroupVersionKind{Kind: "PodExecOptions"},
			UserInfo: authv1.UserInfo{
				Username: "lauren",
				// No matching secret-sauce
				Extra: map[string]authv1.ExtraValue{
					"secret-sauce": {"the-wrong-sauce"},
				},
			},
		},
	}

	rr, parsed := postExecHandler(t, ar, "application/json")
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", rr.Code, http.StatusOK, rr.Body.String())
	}
	if parsed.Response == nil || parsed.Response.Allowed {
		t.Fatalf("expected Allowed=false, got: %+v", parsed.Response)
	}
	if parsed.Response.Result == nil || parsed.Response.Result.Message != "cannot use exec directly, use rexec plugin instead" {
		t.Fatalf("unexpected denial message: %+v", parsed.Response.Result)
	}
}

// --- canPass unit tests ---

func TestCanPassBypassUser(t *testing.T) {
	oldBypass := ByPassedUsers
	t.Cleanup(func() { ByPassedUsers = oldBypass })

	ByPassedUsers = []string{"lauren"}

	rv := admissionv1.AdmissionReview{
		Request: &admissionv1.AdmissionRequest{
			UserInfo: authv1.UserInfo{Username: "lauren"},
		},
	}

	if !canPass(rv) {
		t.Fatal("expected canPass true for bypassed user")
	}
}

func TestCanPassSecretSauceMatch(t *testing.T) {
	oldBypass := ByPassedUsers
	oldSauce := SecretSauce
	t.Cleanup(func() {
		ByPassedUsers = oldBypass
		SecretSauce = oldSauce
	})

	ByPassedUsers = nil
	SecretSauce = "the-right-sauce"

	rv := admissionv1.AdmissionReview{
		Request: &admissionv1.AdmissionRequest{
			UserInfo: authv1.UserInfo{
				Extra: map[string]authv1.ExtraValue{
					"secret-sauce": {"the-right-sauce"},
				},
			},
		},
	}
	if !canPass(rv) {
		t.Fatal("expected canPass true when secret-sauce matches")
	}
}

func TestCanPassNoMatch(t *testing.T) {
	oldBypass := ByPassedUsers
	oldSauce := SecretSauce
	t.Cleanup(func() {
		ByPassedUsers = oldBypass
		SecretSauce = oldSauce
	})

	ByPassedUsers = []string{"lauren"}
	SecretSauce = "the-right-sauce"

	rv := admissionv1.AdmissionReview{
		Request: &admissionv1.AdmissionRequest{
			UserInfo: authv1.UserInfo{
				Username: "not-lauren",
				Extra: map[string]authv1.ExtraValue{
					"secret-sauce": {"the-wrong-sauce"},
				},
			},
		},
	}
	if canPass(rv) {
		t.Fatal("expected canPass false when neither bypass nor sauce matches")
	}
}

// --- waitForListener unit test ---

func TestWaitForListenerReady(t *testing.T) {
	// Save/restore shared map
	oldProxyMap := proxyMap
	t.Cleanup(func() { proxyMap = oldProxyMap })

	// Use a fresh map for isolation
	proxyMap = map[string]bool{}

	// Mark ready before call so it should return quickly
	id := "session-123"
	proxyMap[id] = true

	start := time.Now()
	if err := waitForListener(id); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if time.Since(start) > time.Second {
		t.Fatalf("waitForListener returned too slowly")
	}
}

// --- rexecHandler early validation test ---

func TestRexecHandlerMissingUser(t *testing.T) {
	// No X-Remote-User header
	req := httptest.NewRequest(http.MethodGet,
		"/apis/audit.adyen.internal/v1beta1/namespaces/ns/pods/pod/exec", nil)
	req = mux.SetURLVars(req, map[string]string{
		"namespace": "ns",
		"pod":       "pod",
	})

	rr := httptest.NewRecorder()

	rexecHandler(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusForbidden)
	}
}
