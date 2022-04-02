package webpush

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/xakep666/ecego"
)

type testHTTPClient struct {
	lastReq *http.Request
}

func (c *testHTTPClient) Do(req *http.Request) (*http.Response, error) {
	c.lastReq = req
	return &http.Response{StatusCode: 201}, nil
}

func getURLEncodedTestSubscription() *Subscription {
	return &Subscription{
		Endpoint: "https://updates.push.services.mozilla.com/wpush/v2/gAAAAA",
		Keys: Keys{
			P256dh: "BNNL5ZaTfK81qhXOx23-wewhigUeFb632jN6LvRWCFH1ubQr77FE_9qV1FuojuRmHP42zmf34rXgW80OvUVDgTk",
			Auth:   "zqbxT6JKstKSY9JKibZLSQ",
		},
	}
}

func getStandardEncodedTestSubscription() *Subscription {
	return &Subscription{
		Endpoint: "https://updates.push.services.mozilla.com/wpush/v2/gAAAAA",
		Keys: Keys{
			P256dh: "BNNL5ZaTfK81qhXOx23+wewhigUeFb632jN6LvRWCFH1ubQr77FE/9qV1FuojuRmHP42zmf34rXgW80OvUVDgTk=",
			Auth:   "zqbxT6JKstKSY9JKibZLSQ==",
		},
	}
}

func TestSendNotificationToURLEncodedSubscription(t *testing.T) {
	resp, err := SendNotification([]byte("Test"), getURLEncodedTestSubscription(), &Options{
		HTTPClient:      &testHTTPClient{},
		RecordSize:      3070,
		Subscriber:      "<EMAIL@EXAMPLE.COM>",
		Topic:           "test_topic",
		TTL:             0,
		Urgency:         "low",
		VAPIDPublicKey:  "test-public",
		VAPIDPrivateKey: "test-private",
	})
	if err != nil {
		t.Fatal(err)
	}

	if resp.StatusCode != 201 {
		t.Fatalf(
			"Incorreect status code, expected=%d, got=%d",
			resp.StatusCode,
			201,
		)
	}
}

func TestSendNotificationToStandardEncodedSubscription(t *testing.T) {
	resp, err := SendNotification([]byte("Test"), getStandardEncodedTestSubscription(), &Options{
		HTTPClient:      &testHTTPClient{},
		Subscriber:      "<EMAIL@EXAMPLE.COM>",
		Topic:           "test_topic",
		TTL:             0,
		Urgency:         "low",
		VAPIDPrivateKey: "testKey",
	})
	if err != nil {
		t.Fatal(err)
	}

	if resp.StatusCode != 201 {
		t.Fatalf(
			"Incorreect status code, expected=%d, got=%d",
			resp.StatusCode,
			201,
		)
	}
}

func TestSendTooLargeNotification(t *testing.T) {
	_, err := SendNotification([]byte(strings.Repeat("Test", int(MaxRecordSize))), getStandardEncodedTestSubscription(), &Options{
		HTTPClient:      &testHTTPClient{},
		Subscriber:      "<EMAIL@EXAMPLE.COM>",
		Topic:           "test_topic",
		TTL:             0,
		Urgency:         "low",
		VAPIDPrivateKey: "testKey",
	})
	if err == nil {
		t.Fatalf("Error is nil, expected=%s", ErrMaxPadExceeded)
	}
}

func TestKMGenKey(t *testing.T) {
	mycurve := elliptic.P256()
	priv, _ := ecdsa.GenerateKey(mycurve, rand.Reader)
	pubkey := base64.StdEncoding.EncodeToString(elliptic.Marshal(mycurve, priv.X, priv.Y))
	auth := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16} // 16 bytes long auth value buffer
	_, _ = rand.Read(auth)

	testHTTPC := &testHTTPClient{}

	payload, _ := io.ReadAll(io.LimitReader(rand.Reader, 3993)) // 3993 is max payload length that works to send notification
	_, _ = SendNotification([]byte(payload), &Subscription{Endpoint: "http://example.com", Keys: Keys{P256dh: pubkey, Auth: base64.StdEncoding.EncodeToString(auth)}}, &Options{
		HTTPClient: testHTTPC,
	})

	body, _ := io.ReadAll(testHTTPC.lastReq.Body)

	engine := ecego.NewEngine(ecego.SingleKey(priv), ecego.WithAuthSecret(auth))
	decoded, _ := engine.Decrypt(body, nil, ecego.OperationalParams{Salt: []byte("1234567812345678")}) // any salt, ecego will decode actual salt later

	if !bytes.Equal(payload, decoded) {
		t.Error("Wrong decode", payload, decoded)
	}
}
