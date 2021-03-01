package aws

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"reflect"
	"regexp"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
)

// Base64Encode encodes data if the input isn't already encoded using base64.StdEncoding.EncodeToString.
// If the input is already base64 encoded, return the original input unchanged.
func base64Encode(data []byte) string {
	// Check whether the data is already Base64 encoded; don't double-encode
	if isBase64Encoded(data) {
		return string(data)
	}
	// data has not been encoded encode and return
	return base64.StdEncoding.EncodeToString(data)
}

func isBase64Encoded(data []byte) bool {
	_, err := base64.StdEncoding.DecodeString(string(data))
	return err == nil
}

func looksLikeJsonString(s interface{}) bool {
	return regexp.MustCompile(`^\s*{`).MatchString(s.(string))
}

func jsonBytesEqual(b1, b2 []byte) bool {
	var o1 interface{}
	if err := json.Unmarshal(b1, &o1); err != nil {
		return false
	}

	var o2 interface{}
	if err := json.Unmarshal(b2, &o2); err != nil {
		return false
	}

	return reflect.DeepEqual(o1, o2)
}

func isResourceNotFoundError(err error) bool {
	_, ok := err.(*resource.NotFoundError)
	return ok
}

func isResourceTimeoutError(err error) bool {
	timeoutErr, ok := err.(*resource.TimeoutError)
	return ok && timeoutErr.LastError == nil
}

func appendUniqueString(slice []string, elem string) []string {
	for _, e := range slice {
		if e == elem {
			return slice
		}
	}
	return append(slice, elem)
}

func hashSum(value interface{}) string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(value.(string))))
}

func hashPassword(value interface{}) string {
	return hashSum(value)
}

// Manages password hashing in state file based on hash_password config value.
// Should be called from the update function. Compare old password with new
// and update RDS if no match is found. At the end, hash the password if the
// hash_password config value is true.
func managePasswordHashUpdate(d *schema.ResourceData, key string) (bool, *string) {
	var requiresModification bool

	o_passwd, n_passwd := d.GetChange(key)
	n_passwdHash := hashPassword(n_passwd)


	//Password hasn't changed but it needs to be hashed in the state file
	if o_passwd == n_passwd {
		requiresModification = false
		d.Set(key, n_passwdHash)
	} else if o_passwd == n_passwdHash {
		requiresModification = false
		d.Set(key, n_passwdHash)
	} else {
		requiresModification = true
		d.Set(key, n_passwdHash)
	}

	return requiresModification, aws.String(n_passwd.(string))
}

func resourcePasswordStateUpgrade(d *schema.ResourceData, key string) string{

	hashed_password := d.Get(key).(string)

	return hashed_password
}