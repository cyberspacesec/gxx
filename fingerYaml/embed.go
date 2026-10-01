//go:build embed

package utils

import "github.com/cyberspacesec/gxx/v2/pkg/finger"

func GetFingerPath() string                    { return "embedded://." }
func GetFingerYaml() ([]*finger.Finger, error) { return GetEmbeddedFingerYaml() }
